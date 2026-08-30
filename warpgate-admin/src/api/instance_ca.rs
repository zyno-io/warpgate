use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use warpgate_common::{AdminPermission, WarpgateError};

use super::AdminContext;

#[derive(Object)]
struct InstanceCaCertificate {
    /// PEM-encoded public certificate for the Warpgate instance CA. Install
    /// this certificate in a Kubernetes API server's client-CA trust bundle
    /// before enabling ephemeral-certificate upstream authentication.
    certificate_pem: String,
}

#[derive(ApiResponse)]
enum GetInstanceCaCertificateResponse {
    #[oai(status = 200)]
    Ok(Json<InstanceCaCertificate>),
}

pub struct Api;

#[OpenApi]
impl Api {
    #[oai(
        path = "/instance-ca/certificate",
        method = "get",
        operation_id = "get_instance_ca_certificate"
    )]
    async fn api_get_certificate(
        &self,
        admin: AdminContext,
    ) -> Result<GetInstanceCaCertificateResponse, WarpgateError> {
        admin.require(AdminPermission::ConfigEdit)?;
        let parameters = admin.parameters().await?;
        Ok(GetInstanceCaCertificateResponse::Ok(Json(
            InstanceCaCertificate {
                certificate_pem: parameters.ca_certificate_pem.clone(),
            },
        )))
    }
}
