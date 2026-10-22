import pytest
from fastapi import FastAPI, Header, Request
from fastapi.testclient import TestClient
from adapters.fastapi.middleware import Comply54Middleware

# --- MOCK CLASSES FOR TESTING ---
class MockComplianceResult:
    def __init__(self, is_blocked, messages=None):
        self.is_blocked = is_blocked
        self.primary_violation = type('Violation', (object,), {"messages": messages or []})()

class MockComplianceEngine:
    def __init__(self, should_block=False, messages=None):
        self.should_block = should_block
        self.messages = messages or ["Action blocked by policy"]

    def check(self, action, params):
        return MockComplianceResult(is_blocked=self.should_block, messages=self.messages)

# --- FIXTURES ---
@pytest.fixture
def action_extractor():
    # Simple extractor that pulls an action from a custom header
    return lambda req: (req.headers.get("X-Agent-Action"), {"user_id": "test_user"})

# --- THE 10 ACCEPTANCE TESTS ---

# 1. Test standard allowed request passing through
def test_middleware_allows_valid_request(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=False)
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=action_extractor)

    @app.get("/execute")
    def route():
        return {"status": "success"}

    client = TestClient(app)
    response = client.get("/execute", headers={"X-Agent-Action": "say_hello"})
    assert response.status_code == 200
    assert response.json() == {"status": "success"}

# 2. Test blocked request returns default 422
def test_middleware_blocks_invalid_request(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=True)
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=action_extractor)

    client = TestClient(app)
    response = client.get("/", headers={"X-Agent-Action": "delete_database"})
    assert response.status_code == 422
    assert "blocked" in response.json()["error"]

# 3. Test custom on_block handler payload
def test_custom_on_block_handler(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=True, messages=["Critical compliance failure"])
    
    custom_on_block = lambda res: {"error": res.primary_violation.messages[0], "code": "COMPLIANCE_ERR"}
    app.add_middleware(
        Comply54Middleware, 
        compliance=compliance, 
        action_extractor=action_extractor, 
        on_block=custom_on_block
    )

    client = TestClient(app)
    response = client.get("/", headers={"X-Agent-Action": "unauthorized_action"})
    assert response.status_code == 422
    assert response.json() == {"error": "Critical compliance failure", "code": "COMPLIANCE_ERR"}

# 4. Test request state attachment for downstream route access
def test_compliance_result_attached_to_state(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=False)
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=action_extractor)

    @app.get("/check-state")
    def read_state(request: Request):
        return {"attached": hasattr(request.state, "compliance"), "is_blocked": request.state.compliance.is_blocked}

    client = TestClient(app)
    response = client.get("/check-state", headers={"X-Agent-Action": "safe_action"})
    assert response.status_code == 200
    assert response.json() == {"attached": True, "is_blocked": False}

# 5. Test extractor exception handling defensive fallback
def test_extractor_exception_safety():
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=False)
    
    # Intentional broken extractor
    def broken_extractor(req):
        raise ValueError("Extraction crash")
    
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=broken_extractor)

    @app.get("/")
    def index(): return {"ok": True}

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200  # Should fallback defensively and allow request

# 6. Test missing headers handle correctly
def test_missing_action_header(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=False)
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=action_extractor)

    @app.get("/")
    def index(): return {"ok": True}

    client = TestClient(app)
    response = client.get("/") # No headers sent
    assert response.status_code == 200

# 7. Test multiple query parameters parsing
def test_complex_params_extraction():
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=False)
    complex_extractor = lambda req: ("action", dict(req.query_params))
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=complex_extractor)

    @app.get("/query")
    def run(request: Request):
        return request.state.compliance.is_blocked

    client = TestClient(app)
    response = client.get("/query?amount=500&currency=USD")
    assert response.status_code == 200

# 8. Test middleware handling with alternative HTTP verbs (POST)
def test_post_request_handling(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=True)
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=action_extractor)

    client = TestClient(app)
    response = client.post("/submit", headers={"X-Agent-Action": "restricted_post"})
    assert response.status_code == 422

# 9. Test middleware handling with PUT requests
def test_put_request_handling(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=False)
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=action_extractor)

    @app.put("/update")
    def update(): return {"updated": True}

    client = TestClient(app)
    response = client.put("/update", headers={"X-Agent-Action": "allowed_put"})
    assert response.status_code == 200

# 10. Test middleware execution chain when no middleware logic matches
def test_empty_action_handling(action_extractor):
    app = FastAPI()
    compliance = MockComplianceEngine(should_block=False)
    app.add_middleware(Comply54Middleware, compliance=compliance, action_extractor=action_extractor)

    @app.get("/status")
    def status(): return {"alive": True}

    client = TestClient(app)
    response = client.get("/status", headers={"X-Agent-Action": ""})
    assert response.status_code == 200

# Helper function to raise exceptions inside a lambda for Test #5
def raise_(ex):
    raise ex