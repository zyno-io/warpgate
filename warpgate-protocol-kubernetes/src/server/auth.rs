use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context;
use poem::Request;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;
use warpgate_aws::EksClusterInfo;
use warpgate_ca::{deserialize_certificate, serialize_certificate_serial};
use warpgate_common::auth::{
    AuthCredential, AuthResult, AuthState, AuthStateUserInfo, CredentialKind,
};
use warpgate_common::{SessionId, TargetKubernetesOptions, TargetOptions, User};
use warpgate_common_http::logging::get_client_ip_addr;
use warpgate_core::auth::submit_credential;
use warpgate_core::login_protection::FailedAttemptInfo;
use warpgate_core::{
    AuthorizedIdentity, ConfigProvider, Services, TargetAuthorization,
    authorize_active_self_service_ticket, authorize_for_target, has_active_self_service_ticket,
    vet_credential_bearer, wait_for_auth_completion,
};
use warpgate_db_entities::{CertificateCredential, CertificateRevocation};

use crate::server::client_certs::RequestCertificateExt;

pub fn unauthorized() -> poem::Error {
    poem::Error::from_string(
        "Unauthorized: provide a valid Bearer token or client certificate",
        poem::http::StatusCode::UNAUTHORIZED,
    )
}

fn access_denied(target_name: &str) -> poem::Error {
    poem::Error::from_string(
        format!("Access denied to target: {target_name}"),
        poem::http::StatusCode::FORBIDDEN,
    )
}

/// A Kubernetes request's proven identity. OIDC is kept distinct from other
/// user credentials because a self-service ticket is a grant for a federated
/// identity, not a substitute bearer credential.
#[derive(Clone)]
pub enum KubernetesAuthentication {
    User(User),
    Oidc {
        user: User,
        credential: AuthCredential,
    },
}

impl KubernetesAuthentication {
    pub fn user_info(&self) -> AuthStateUserInfo {
        match self {
            Self::User(user) | Self::Oidc { user, .. } => user.into(),
        }
    }

    fn user(&self) -> &User {
        match self {
            Self::User(user) | Self::Oidc { user, .. } => user,
        }
    }

    fn oidc_user(&self) -> Option<&User> {
        match self {
            Self::User(_) => None,
            Self::Oidc { user, .. } => Some(user),
        }
    }

    fn credential(&self) -> Option<&AuthCredential> {
        match self {
            Self::User(_) => None,
            Self::Oidc { credential, .. } => Some(credential),
        }
    }

    pub fn authentication_source(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Oidc { .. } => "oidc",
        }
    }
}

/// A Kubernetes target authorization.  Tickets deliberately stay server-side:
/// the browser activation grants the authenticated OIDC user access, and the
/// ticket is rechecked before every proxied request.
#[derive(Clone)]
pub struct KubernetesTargetAuthorization {
    authorization: TargetAuthorization,
    ticket_grant: bool,
}

impl KubernetesTargetAuthorization {
    fn from_role(authorization: TargetAuthorization) -> Self {
        Self {
            authorization,
            ticket_grant: false,
        }
    }

    fn from_ticket(authorization: TargetAuthorization) -> Self {
        Self {
            authorization,
            ticket_grant: true,
        }
    }

    pub async fn verify_current(
        &self,
        authentication: &KubernetesAuthentication,
        services: &Services,
    ) -> poem::Result<()> {
        if !self.ticket_grant {
            return Ok(());
        }
        let Some(user) = authentication.oidc_user() else {
            return Err(unauthorized());
        };

        if has_active_self_service_ticket(&services.db, user.id, self.authorization.target().id)
            .await?
        {
            Ok(())
        } else {
            Err(access_denied(&self.authorization.target().name))
        }
    }

    pub fn into_parts(self) -> (AuthStateUserInfo, warpgate_common::Target) {
        self.authorization.into_parts()
    }
}

/// What kind of credential the client presented, for audit and rate-limiting.
/// `None` means no credential was presented at all — an unauthenticated probe,
/// not a failed login attempt.
fn presented_credential_kind(req: &Request) -> Option<&'static str> {
    let has_bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));
    if has_bearer {
        Some("token")
    } else if req.client_certificate().is_some() {
        Some("certificate")
    } else {
        None
    }
}

/// Emit the shared `UserAuthenticationFailed1` audit event. A failed Kubernetes
/// auth has no established session, so a fresh id tags this attempt.
fn emit_authentication_failed(client_ip: Option<IpAddr>, credential_type: &str, reason: &str) {
    let client_ip = client_ip.map_or_else(|| "<unknown>".to_string(), |ip| ip.to_string());
    info!(
        target: "audit",
        _type = "UserAuthenticationFailed1",
        session = %Uuid::new_v4(),
        client_ip = %client_ip,
        username = "",
        credentials = %credential_type,
        reason = %reason,
        "Authentication failed",
    );
}

/// Resolve and vet the caller's identity from the request's transport credentials
/// (API token / OIDC token / client certificate). Runs on *every* request — it
/// must, both to attribute the request to a session and to re-check the credential
/// and account status — so it is deliberately cheap: no auth state, no web
/// approval. `Err(unauthorized)` on any failure.
pub async fn authenticate_kubernetes_user(
    req: &Request,
    services: &Services,
) -> poem::Result<KubernetesAuthentication> {
    let client_ip = get_client_ip_addr(req, services).await;

    // Fail closed if login protection currently has this source IP blocked.
    if let Some(ip) = client_ip
        && services
            .login_protection
            .check_ip_blocked(&ip)
            .await?
            .is_some()
    {
        warn!(ip = %ip, "Kubernetes auth attempt from blocked IP");
        return Err(unauthorized());
    }

    let credential_kind = presented_credential_kind(req);

    let Some(authentication) = authenticate(req, services).await? else {
        // A presented-but-invalid credential counts toward brute-force
        // protection and is audited; a request with no credential at all is a
        // plain unauthenticated probe and is neither recorded nor audited.
        if let (Some(ip), Some(kind)) = (client_ip, credential_kind) {
            let _ = services
                .login_protection
                .record_failed_attempt(FailedAttemptInfo {
                    username: String::new(),
                    remote_ip: ip,
                    protocol: crate::PROTOCOL_NAME,
                    credential_type: kind.to_string(),
                })
                .await;
            emit_authentication_failed(client_ip, kind, "no matching credential");
        }
        return Err(unauthorized());
    };

    if !vet_credential_bearer(&services.login_protection, authentication.user(), client_ip).await? {
        return Err(unauthorized());
    }

    // A validated transport credential clears the failed-attempt counter.
    if let Some(ip) = client_ip {
        let user_info = authentication.user_info();
        let _ = services
            .login_protection
            .clear_failed_attempts(&ip, &user_info.username)
            .await;
    }

    Ok(authentication)
}

/// Authorize an already-authenticated user for a Kubernetes target, applying the
/// credential policy. A verified OIDC identity supplies the policy's `sso`
/// credential; an optional `web` factor may still block. This is the expensive
/// step, so the caller caches the result per correlated session so it runs once
/// per session (one approval per `kubectl` command's fan-out of requests)
/// rather than once per request.
///
/// `session_id` is that of the session the caller has registered for this
/// request: the auth state is keyed by it, which is what lets a web approval
/// raised on another node be routed back to the waiting request.
pub async fn authorize_kubernetes_target(
    req: &Request,
    authentication: &KubernetesAuthentication,
    target_name: &str,
    session_id: SessionId,
    services: &Services,
) -> poem::Result<KubernetesTargetAuthorization> {
    let target = lookup_k8s_target(services.config_provider.as_ref(), target_name).await?;

    // A self-service ticket is a server-side JIT authorization grant for the
    // person whose OIDC token authenticated this request.  It is intentionally
    // checked before credential-policy web approval: activating the approved
    // ticket is the explicit, audited approval step for this target.
    if let Some(user) = authentication.oidc_user()
        && let Some(authorization) = authorize_active_self_service_ticket(
            &services.db,
            user.into(),
            target.clone(),
            crate::PROTOCOL_NAME,
        )
        .await?
    {
        return Ok(KubernetesTargetAuthorization::from_ticket(authorization));
    }

    let user = authentication.user();
    let client_ip = get_client_ip_addr(req, services).await;

    // When the user has a Kubernetes credential policy, enforce it against the
    // verified transport credential; otherwise use the identity directly.
    let identity = authorize_kubernetes_identity(
        services,
        authentication,
        user,
        client_ip,
        target_name,
        session_id,
    )
    .await?;
    authorize_for_target(services.config_provider.as_ref(), &identity, target)
        .await?
        .map(KubernetesTargetAuthorization::from_role)
        .ok_or_else(|| access_denied(target_name))
}

/// Turn a validated Kubernetes identity into an [`AuthorizedIdentity`], applying
/// the user's Kubernetes credential policy when one is configured.
///
/// Transport authentication (WG API token, OIDC token, or client certificate)
/// establishes *who* the caller is — it is the identity, verified out of band by
/// [`authenticate`]. A verified OIDC token additionally supplies an `sso`
/// credential to the policy. API-token and client-certificate authentication do
/// not, so they cannot satisfy a Kubernetes `sso` requirement.
///
/// With no policy the transport identity is used directly. With one, a fresh auth
/// state enforces the web approval, cleared either by a cached grace-period bypass
/// or by the user approving the pending request in the Warpgate UI while the
/// request waits (kubectl has no default client timeout; the auth-state TTL bounds
/// the wait).
async fn authorize_kubernetes_identity(
    services: &Services,
    authentication: &KubernetesAuthentication,
    user: &User,
    client_ip: Option<IpAddr>,
    target_name: &str,
    session_id: SessionId,
) -> poem::Result<AuthorizedIdentity> {
    let policy_configured = user
        .credential_policy
        .as_ref()
        .and_then(|p| p.kubernetes.as_ref())
        .is_some_and(|kinds| !kinds.is_empty());

    if !policy_configured {
        return Ok(AuthorizedIdentity::for_authenticated_session(
            user.into(),
            crate::PROTOCOL_NAME,
        ));
    }

    let mut supported_credential_types = vec![CredentialKind::WebUserApproval];
    if let Some(credential) = authentication.credential() {
        supported_credential_types.push(credential.kind());
    }

    let state_arc = services
        .create_auth_state(
            &session_id,
            &user.username,
            crate::PROTOCOL_NAME,
            target_name,
            &supported_credential_types,
            client_ip,
            None,
        )
        .await?;

    if let Some(credential) = authentication.credential() {
        let outcome = {
            let mut state = state_arc.lock().await;
            submit_credential(
                &mut state,
                credential.clone(),
                services.config_provider.as_ref(),
            )
            .await?
        };
        if !outcome.is_valid() {
            warn!(username = %user.username, "Kubernetes OIDC credential rejected");
            return Err(unauthorized());
        }
    }

    await_kubernetes_credential_policy(services, user, &state_arc).await
}

/// Resolves the credential policy, waiting only when it additionally requires
/// browser approval.
async fn await_kubernetes_credential_policy(
    services: &Services,
    user: &User,
    state_arc: &Arc<Mutex<AuthState>>,
) -> poem::Result<AuthorizedIdentity> {
    loop {
        let verification = state_arc.lock().await.verify();
        match verification {
            AuthResult::Accepted { .. } => {
                return AuthorizedIdentity::from_auth_state(&*state_arc.lock().await)
                    .ok_or_else(unauthorized);
            }
            AuthResult::Need(kinds) if kinds.contains(&CredentialKind::WebUserApproval) => {
                if services.try_web_approval_bypass(state_arc).await? {
                    continue;
                }
                if !matches!(
                    wait_for_auth_completion(state_arc).await,
                    AuthResult::Accepted { .. }
                ) {
                    warn!(username = %user.username, "Kubernetes web approval not granted");
                    return Err(unauthorized());
                }
            }
            // An OIDC identity may satisfy `sso`, and browser approval can
            // satisfy `web`. Other outstanding factors cannot be collected from
            // a non-interactive Kubernetes client.
            AuthResult::Need(_) | AuthResult::Rejected => {
                warn!(username = %user.username, "Kubernetes credential policy not satisfiable");
                return Err(unauthorized());
            }
        }
    }
}

/// Resolve the caller's identity from the request's transport credentials (WG API
/// token, OIDC bearer token, or client certificate). Each is verified here and
/// establishes *who* the caller is; that transport auth is the identity, so the
/// caller may also submit a verified OIDC identity to its credential policy.
/// Returns `None` if no presented credential validated; genuine
/// lookup/verification errors propagate rather than being treated as a failure.
async fn authenticate(
    req: &Request,
    services: &Services,
) -> poem::Result<Option<KubernetesAuthentication>> {
    // Bearer token authentication (API tokens, then OIDC ID tokens).
    if let Some(auth_header) = req.headers().get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        if let Ok(Some(user)) = services.config_provider.validate_api_token(token).await {
            return Ok(Some(KubernetesAuthentication::User(user)));
        }

        // API token did not match — try OIDC ID token validation against any SSO
        // provider that has opted into Kubernetes OIDC.
        let sso_providers = {
            let config = services.config.lock().await;
            config.store.sso_providers.clone()
        };

        // Routing hint: only a provider whose issuer matches the token can
        // verify it, so we avoid issuer-discovery network calls to the others.
        let token_issuer = warpgate_sso::unverified_issuer(token);

        for provider_config in sso_providers.iter().filter(|p| p.kubernetes.is_some()) {
            if let Some(ref token_issuer) = token_issuer
                && let Ok(provider_issuer) = provider_config.provider.issuer_url()
                && provider_issuer.url().as_str().trim_end_matches('/')
                    != token_issuer.trim_end_matches('/')
            {
                continue;
            }

            let client = match warpgate_sso::SsoClient::new(provider_config.provider.clone()) {
                Ok(c) => c,
                Err(e) => {
                    debug!(provider = %provider_config.name, error = %e, "Skipping SSO provider (client init failed)");
                    continue;
                }
            };

            let response = match client.verify_id_token_to_response(token).await {
                Ok(r) => r,
                Err(e) => {
                    // Wrong issuer / audience / signature for this provider — try the next.
                    debug!(provider = %provider_config.name, error = %e, "OIDC token not valid for provider");
                    continue;
                }
            };

            // Warpgate's canonical SSO resolver keys a user linkage on the
            // provider and verified email. This is also the identity bound to
            // an SSO credential policy and a server-side ticket grant, so an
            // OIDC token without an email claim cannot authenticate here.
            let Some(email) = response.email.clone() else {
                continue;
            };

            let Some(username) = warpgate_core::resolve_and_map_sso_user(
                services.config_provider.as_ref(),
                provider_config,
                &response,
            )
            .await
            .map_err(|e| {
                poem::Error::from_string(
                    format!("SSO user resolution failed: {e}"),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                )
            })?
            else {
                continue;
            };

            let user = user_for_username(services, &username).await?;
            let credential = AuthCredential::Sso {
                provider: provider_config.name.clone(),
                email,
            };
            return Ok(Some(KubernetesAuthentication::Oidc { user, credential }));
        }
    }

    // Client certificate authentication, using the certificate extracted by the
    // middleware if present.
    if let Some(client_cert) = req.client_certificate() {
        debug!("Found client certificate from middleware, validating against database");

        match validate_client_certificate(&client_cert.der_bytes, services).await {
            Ok(Some(user)) => return Ok(Some(KubernetesAuthentication::User(user))),
            Ok(None) => debug!("Client certificate provided but not found in database"),
            // A rejected certificate returns `Ok(None)`; an `Err` is a fault in the
            // certificate store (DB) or an unparseable cert, not a credential
            // decision. Surfacing it as 500 keeps an outage from masquerading as a
            // bad certificate.
            Err(e) => {
                return Err(poem::Error::from_string(
                    format!("Client certificate validation failed: {e}"),
                    poem::http::StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        }
    } else {
        debug!("No client certificate provided in TLS connection");
    }

    Ok(None)
}

/// Look up a Kubernetes target by name before authorizing it through either an
/// access role or an active self-service ticket.
async fn lookup_k8s_target<C: ConfigProvider + Send>(
    config_provider: &C,
    target_name: &str,
) -> poem::Result<warpgate_common::Target> {
    config_provider
        .get_target_by_name(target_name)
        .await
        .context("looking up target")?
        .filter(|t| matches!(t.options, TargetOptions::Kubernetes(_)))
        .ok_or_else(|| {
            poem::Error::from_string(
                format!("Kubernetes target not found: {target_name}"),
                poem::http::StatusCode::NOT_FOUND,
            )
        })
}

/// Load a resolved SSO user by username.
async fn user_for_username(services: &Services, username: &str) -> poem::Result<User> {
    let db = &services.db;
    let model = warpgate_db_entities::User::Entity::find()
        .filter(warpgate_db_entities::User::Entity::username_eq_ci(username))
        .one(db)
        .await
        .context("looking up user in database")?
        .ok_or_else(|| {
            poem::Error::from_string(
                format!("User not found after SSO resolution: {username}"),
                poem::http::StatusCode::UNAUTHORIZED,
            )
        })?;
    User::try_from(model).map_err(|e| {
        poem::Error::from_string(
            format!("Failed to convert user model: {e}"),
            poem::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    })
}

pub async fn create_authenticated_client(
    k8s_options: &TargetKubernetesOptions,
    _auth_user: Option<&String>,
    _services: &Services,
) -> anyhow::Result<reqwest::ClientBuilder> {
    debug!(
        server_url = ?k8s_options.cluster_url,
        auth_kind = ?k8s_options.auth,
        tls_config = ?k8s_options.tls,
        "Creating authenticated Kubernetes client"
    );

    // Create HTTP client with the configuration
    let mut client_builder = reqwest::Client::builder();

    if !k8s_options.tls.verify {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    match &k8s_options.auth {
        warpgate_common::KubernetesTargetAuth::Token(auth) => {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    auth.token.reveal()?.expose_secret()
                ))
                .context("setting Authorization header")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
        warpgate_common::KubernetesTargetAuth::Certificate(auth) => {
            // Expect PEM certificate and PEM private key in the auth config
            // Combine into a single PEM bundle for reqwest::Identity
            let cert_pem = auth.certificate.expose_secret();
            let key_pem = auth.private_key.reveal()?;
            let pem_bundle = format!(
                "{}\n{}\n",
                cert_pem.trim_end_matches('\n'),
                key_pem.expose_secret().trim_end_matches('\n')
            );

            let identity = reqwest::Identity::from_pem(pem_bundle.as_bytes())
                .context("Invalid client certificate/key for Kubernetes upstream")?;
            client_builder = client_builder.identity(identity);
        }
        warpgate_common::KubernetesTargetAuth::IamRole(_) => {
            // EKS IAM role authentication: generate a token from the cluster URL
            let EksClusterInfo { name, region } =
                warpgate_aws::find_eks_cluster_by_url(&k8s_options.cluster_url)
                    .await
                    .context("EKS cluster lookup")?;

            let token = warpgate_aws::generate_eks_token(&name, &region)
                .await
                .context("EKS token generation")?;

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("setting Authorization header for EKS token")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
    }

    Ok(client_builder)
}

/// True if `now` falls within the certificate's `[not_before, not_after]`
/// validity window (bounds inclusive).
fn cert_is_currently_valid(not_before: SystemTime, not_after: SystemTime, now: SystemTime) -> bool {
    now >= not_before && now <= not_after
}

// Helper function to validate client certificate against database
pub async fn validate_client_certificate(
    cert_der: &[u8],
    services: &Services,
) -> anyhow::Result<Option<User>> {
    // Convert DER to PEM format for comparison
    let cert_pem = der_to_pem(cert_der);

    let db = &services.db;

    let cert = deserialize_certificate(&cert_pem)?;

    // Reject certificates outside their validity period.
    let validity = &cert.tbs_certificate.validity;
    if !cert_is_currently_valid(
        validity.not_before.to_system_time(),
        validity.not_after.to_system_time(),
        SystemTime::now(),
    ) {
        warn!("Client certificate is outside its validity period");
        return Ok(None);
    }

    // Check if certificate is revoked (by serial number)
    let serial_b64 = serialize_certificate_serial(&cert);
    if CertificateRevocation::Entity::find()
        .filter(CertificateRevocation::Column::SerialNumberBase64.eq(&serial_b64))
        .one(db)
        .await?
        .is_some()
    {
        warn!(serial = %serial_b64, "Client certificate is revoked");
        return Ok(None);
    }

    // Find all certificate credentials and match against the provided certificate
    let cert_credentials = CertificateCredential::Entity::find()
        .find_with_related(warpgate_db_entities::User::Entity)
        .all(db)
        .await?;

    for (cert_credential, users) in cert_credentials {
        if let Some(user) = users.into_iter().next() {
            // Normalize both certificates for comparison
            let stored_cert = normalize_certificate_pem(&cert_credential.certificate_pem);
            let provided_cert = normalize_certificate_pem(&cert_pem);

            if stored_cert == provided_cert {
                debug!(
                    user = user.username,
                    cert_label = cert_credential.label,
                    "Client certificate validated for user"
                );

                // Update last_used timestamp
                let mut active_model: CertificateCredential::ActiveModel = cert_credential.into();
                active_model.last_used = Set(Some(OffsetDateTime::now_utc()));
                if let Err(e) = active_model.update(db).await {
                    warn!("Failed to update certificate last_used timestamp: {}", e);
                }

                return Ok(Some(User::try_from(user)?));
            }
        }
    }

    Ok(None)
}

fn der_to_pem(der_bytes: &[u8]) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose;
    let cert_b64 = general_purpose::STANDARD.encode(der_bytes);
    let cert_lines: Vec<String> = cert_b64
        .chars()
        .collect::<Vec<char>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect();

    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        cert_lines.join("\n")
    )
}

fn normalize_certificate_pem(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}
