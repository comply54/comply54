import typing

# 1. Mandatory Acceptance Criteria: Optional dependency guard
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except ImportError:
    raise ImportError(
        "FastAPI/Starlette is required to use the Comply54Middleware adapter. "
        "Please install them using: pip install fastapi starlette"
    )

class Comply54Middleware(BaseHTTPMiddleware):
    def __init__(
        self, 
        app: typing.Any, 
        compliance: typing.Any, 
        action_extractor: typing.Callable[[Request], typing.Tuple[str, typing.Dict[str, typing.Any]]], 
        on_block: typing.Optional[typing.Callable[[typing.Any], typing.Dict[str, typing.Any]]] = None
    ):
        """
        FastAPI/Starlette Middleware adapter for comply54.
        
        :param app: The ASGI application instance.
        :param compliance: The compliance instance (e.g., NigeriaFintechCompliance).
        :param action_extractor: A callable taking a Request and returning a tuple of (action_name, params_dict).
        :param on_block: An optional callable taking a ComplianceResult and returning a custom error dictionary payload.
        """
        super().__init__(app)
        self.compliance = compliance
        self.action_extractor = action_extractor
        self.on_block = on_block

    async def dispatch(self, request: Request, call_next: typing.Callable[[Request], typing.Awaitable[Response]]) -> Response:
        # 1. Extract action and parameters using the user-provided extractor
        try:
            action, params = self.action_extractor(request)
        except Exception as e:
            # Fallback defensively if the extractor itself crashes due to an unexpected request structure
            action, params = None, {}

        # 2. Run the compliance engine check
        # NOTE: Ensure this call matches compliance.check(...) signature within the codebase
        result = self.compliance.check(action=action, params=params)

        # 3. Behavior Rule: If the check is blocked, intercept and return an error immediately
        # Adjust 'result.is_blocked' or 'result.blocked' depending on the exact property comply54 uses
        if getattr(result, "is_blocked", False) or getattr(result, "blocked", False):
            status_code = 422
            
            if self.on_block:
                error_content = self.on_block(result)
                return JSONResponse(content=error_content, status_code=status_code)
                
            # Default fallback message if no custom handler is passed
            return JSONResponse(
                content={"error": "Action blocked due to compliance violation."}, 
                status_code=status_code
            )

        # 4. Behavior Rule: If allowed, attach the ComplianceResult to request.state.compliance
        request.state.compliance = result

        # 5. Pass the request forward down the route pipeline
        response = await call_next(request)
        return response