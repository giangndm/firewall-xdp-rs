use poem::{web::Data, Result};
use poem_openapi::{param::Path, payload::Json, Object, OpenApi};
use tokio::sync::oneshot::{self, Sender};

use super::{ApiResult, HttpCmd, HttpContext};

pub struct ControlApi;

#[derive(Object)]
pub struct Rule {
    pub ip: String,
    pub port_begin: u16,
    pub port_end: u16,
}

pub enum ControlApiCmd {
    SetBlacklistSourceRule(Rule, Sender<ApiResult<String>>),
    DelBlacklistSourceRule(String, Sender<ApiResult<String>>),
    SetBlacklistDestRule(Rule, Sender<ApiResult<String>>),
    DelBlacklistDestRule(String, Sender<ApiResult<String>>),
}

#[OpenApi]
impl ControlApi {
    /// Set a source blacklist rule
    #[oai(path = "/rules/blacklist/source", method = "post")]
    async fn set_source_rule(
        &self,
        ctx: Data<&HttpContext>,
        rule: Json<Rule>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::SetBlacklistSourceRule(
                rule.0, tx,
            )))
            .await.expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Del a source blacklist rule
    #[oai(path = "/rules/blacklist/source/:ip", method = "post")]
    async fn del_source_rule(
        &self,
        ctx: Data<&HttpContext>,
        ip: Path<String>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::DelBlacklistSourceRule(
                ip.0, tx,
            )))
            .await.expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Set a dest blacklist rule
    #[oai(path = "/rules/blacklist/dest", method = "post")]
    async fn set_dest_rule(
        &self,
        ctx: Data<&HttpContext>,
        rule: Json<Rule>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::SetBlacklistDestRule(
                rule.0, tx,
            )))
            .await.expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Del a dest blacklist rule
    #[oai(path = "/rules/blacklist/dest/:ip", method = "post")]
    async fn del_dest_rule(
        &self,
        ctx: Data<&HttpContext>,
        ip: Path<String>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::DelBlacklistDestRule(
                ip.0, tx,
            )))
            .await.expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }
}
