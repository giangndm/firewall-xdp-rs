use std::{collections::HashMap, net::Ipv4Addr};

use poem::{web::Data, Result};
use poem_openapi::{param::Path, payload::Json, OpenApi};
use tokio::sync::oneshot::{self, Sender};

use super::{ApiResult, HttpCmd, HttpContext};

pub struct ControlApi;

pub enum ControlApiCmd {
    SetBlacklistSourceRule(String, Sender<ApiResult<String>>),
    DelBlacklistSourceRule(String, Sender<ApiResult<String>>),
    SetWhitelistSourceRule(String, Sender<ApiResult<String>>),
    DelWhitelistSourceRule(String, Sender<ApiResult<String>>),
    SetBlacklistPortRule(u16, Sender<ApiResult<String>>),
    DelBlacklistPortRule(u16, Sender<ApiResult<String>>),
    Reload(Sender<ApiResult<String>>),
    BlockedStats(Sender<ApiResult<HashMap<u16, u64>>>),
}

#[OpenApi]
impl ControlApi {
    /// Set a source blacklist rule
    #[oai(path = "/rules/blacklist/source/:ip", method = "post")]
    async fn set_blacklist_source_rule(
        &self,
        ctx: Data<&HttpContext>,
        ip: Path<String>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::SetBlacklistSourceRule(
                ip.0, tx,
            )))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Del a source blacklist rule
    #[oai(path = "/rules/blacklist/source/:ip", method = "post")]
    async fn del_blacklist_source_rule(
        &self,
        ctx: Data<&HttpContext>,
        ip: Path<String>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::DelBlacklistSourceRule(
                ip.0, tx,
            )))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Set a source blacklist rule
    #[oai(path = "/rules/whitelist/source/:ip", method = "post")]
    async fn set_whitelist_source_rule(
        &self,
        ctx: Data<&HttpContext>,
        ip: Path<String>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::SetWhitelistSourceRule(
                ip.0, tx,
            )))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Del a source blacklist rule
    #[oai(path = "/rules/whitelist/source/:ip", method = "post")]
    async fn del_whitelist_source_rule(
        &self,
        ctx: Data<&HttpContext>,
        ip: Path<String>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::DelWhitelistSourceRule(
                ip.0, tx,
            )))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Set a port blacklist rule
    #[oai(path = "/rules/blacklist/port/:port", method = "post")]
    async fn set_port_rule(
        &self,
        ctx: Data<&HttpContext>,
        port: Path<u16>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::SetBlacklistPortRule(
                port.0, tx,
            )))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Del a port blacklist rule
    #[oai(path = "/rules/blacklist/port/:port", method = "delete")]
    async fn del_port_rule(
        &self,
        ctx: Data<&HttpContext>,
        port: Path<u16>,
    ) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::DelBlacklistPortRule(
                port.0, tx,
            )))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Set a source blacklist rule
    #[oai(path = "/rules/reload", method = "get")]
    async fn reload_rule(&self, ctx: Data<&HttpContext>) -> Result<Json<ApiResult<String>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::Reload(tx)))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }

    /// Set a source blacklist rule
    #[oai(path = "/stats/blocked", method = "get")]
    async fn stats_blocked(
        &self,
        ctx: Data<&HttpContext>,
    ) -> Result<Json<ApiResult<HashMap<u16, u64>>>> {
        let (tx, rx) = oneshot::channel();
        ctx.tx
            .send(HttpCmd::ControlApi(ControlApiCmd::BlockedStats(tx)))
            .await
            .expect("Should work");

        match rx.await {
            Ok(res) => Ok(Json(res)),
            Err(_) => Ok(Json(ApiResult::error("INTERNAL_QUEUE_ERROR"))),
        }
    }
}
