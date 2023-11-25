use poem::{listener::TcpListener, middleware::Cors, EndpointExt, Result, Route, Server};
use poem_openapi::{
    types::{ParseFromJSON, ToJSON, Type},
    Object, OpenApiService,
};
use tokio::sync::mpsc::Sender;

mod control_api;

use control_api::ControlApi;
pub use control_api::ControlApiCmd;

#[derive(Object, Debug)]
pub struct ApiResult<D: ParseFromJSON + ToJSON + Type + Send + Sync> {
    status: bool,
    error: Option<String>,
    data: Option<D>,
}

impl<T: ParseFromJSON + ToJSON + Type + Send + Sync> ApiResult<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: true,
            error: None,
            data: Some(data),
        }
    }

    pub fn error(error: &str) -> Self {
        Self {
            status: false,
            error: Some(error.to_string()),
            data: None,
        }
    }
}

pub enum HttpCmd {
    ControlApi(ControlApiCmd),
}

#[derive(Clone)]
pub struct HttpContext {
    tx: Sender<HttpCmd>,
}

pub async fn start_http_server(
    tx: Sender<HttpCmd>,
    addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = HttpContext { tx };
    let control_api_service = OpenApiService::new(
        ControlApi,
        "Software Defined Firewall API",
        env!("CARGO_PKG_VERSION"),
    )
    .server("/");
    let ui = control_api_service.swagger_ui();
    let spec = control_api_service.spec();
    let route = Route::new()
        .nest("/", control_api_service)
        .nest("/ui", ui)
        .at("/spec", poem::endpoint::make_sync(move |_| spec.clone()))
        .with(Cors::new())
        .data(ctx);
    Server::new(TcpListener::bind(addr)).run(route).await?;
    Ok(())
}
