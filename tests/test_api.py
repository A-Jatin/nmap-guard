"""
Tests for the API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from nmap_guard.api.main import app
from nmap_guard.db.models import Base, User
from nmap_guard.api.dependencies import get_db, get_current_active_user
from nmap_guard.api.schemas import ScanType, ScanStatus

# Test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Test data
test_user = {
    "username": "testuser",
    "email": "test@example.com",
    "password": "testpassword123",
    "is_active": True
}

test_admin = {
    "username": "admin",
    "email": "admin@example.com",
    "password": "adminpassword123",
    "is_active": True,
    "is_admin": True
}

test_scan_config = {
    "name": "Test Config",
    "description": "Test scan configuration",
    "targets": "192.168.1.1",
    "ports": "80,443",
    "scan_type": ScanType.BASIC,
    "timing_template": 3,
    "service_detection": True,
    "os_detection": False,
    "script_scan": False
}

@pytest.fixture
def test_db():
    """Create test database."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session():
    """Database session for testing."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture
def client(test_db, db_session):
    """Test client with database session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)

@pytest.fixture
def test_user_token(client, db_session):
    """Create test user and return authentication token."""
    # Create user
    response = client.post("/api/v1/users/", json=test_user)
    assert response.status_code == 201
    
    # Get token
    response = client.post("/api/v1/token", data={
        "username": test_user["username"],
        "password": test_user["password"]
    })
    assert response.status_code == 200
    return response.json()["access_token"]

@pytest.fixture
def test_admin_token(client, db_session):
    """Create admin user and return authentication token."""
    # Create admin
    response = client.post("/api/v1/users/", json=test_admin)
    assert response.status_code == 201
    
    # Get token
    response = client.post("/api/v1/token", data={
        "username": test_admin["username"],
        "password": test_admin["password"]
    })
    assert response.status_code == 200
    return response.json()["access_token"]

def test_read_main(client):
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Welcome to NMAP-Guard API" in response.json()["message"]

def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_create_user(client, test_admin_token):
    """Test user creation."""
    headers = {"Authorization": f"Bearer {test_admin_token}"}
    response = client.post(
        "/api/v1/users/",
        headers=headers,
        json={
            "username": "newuser",
            "email": "new@example.com",
            "password": "newpassword123",
            "is_active": True
        }
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "new@example.com"
    assert "password" not in data

def test_create_scan_config(client, test_user_token):
    """Test scan configuration creation."""
    headers = {"Authorization": f"Bearer {test_user_token}"}
    response = client.post(
        "/api/v1/configs/",
        headers=headers,
        json=test_scan_config
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == test_scan_config["name"]
    assert data["targets"] == test_scan_config["targets"]

def test_list_scan_configs(client, test_user_token):
    """Test listing scan configurations."""
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    # Create a config first
    client.post("/api/v1/configs/", headers=headers, json=test_scan_config)
    
    # List configs
    response = client.get("/api/v1/configs/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) > 0
    assert data[0]["name"] == test_scan_config["name"]

def test_create_scan(client, test_user_token):
    """Test scan creation."""
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    # Create config first
    config_response = client.post(
        "/api/v1/configs/",
        headers=headers,
        json=test_scan_config
    )
    config_id = config_response.json()["id"]
    
    # Create scan
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"config_id": config_id}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["config_id"] == config_id
    assert data["status"] == ScanStatus.PENDING

def test_get_scan_results(client, test_user_token):
    """Test getting scan results."""
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    # Create config and scan first
    config_response = client.post(
        "/api/v1/configs/",
        headers=headers,
        json=test_scan_config
    )
    config_id = config_response.json()["id"]
    
    scan_response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"config_id": config_id}
    )
    scan_id = scan_response.json()["id"]
    
    # Get scan results
    response = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == scan_id
    assert "status" in data

def test_generate_report(client, test_user_token):
    """Test report generation."""
    headers = {"Authorization": f"Bearer {test_user_token}"}
    
    # Create config and scan first
    config_response = client.post(
        "/api/v1/configs/",
        headers=headers,
        json=test_scan_config
    )
    config_id = config_response.json()["id"]
    
    scan_response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"config_id": config_id}
    )
    scan_id = scan_response.json()["id"]
    
    # Generate report
    response = client.post(
        "/api/v1/reports/generate",
        headers=headers,
        json={
            "scan_id": scan_id,
            "report_type": "summary",
            "format": "json"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert "summary" in data

def test_unauthorized_access(client):
    """Test unauthorized access to protected endpoints."""
    # Try to access protected endpoint without token
    response = client.get("/api/v1/scans/")
    assert response.status_code == 401
    
    # Try to access with invalid token
    headers = {"Authorization": "Bearer invalid_token"}
    response = client.get("/api/v1/scans/", headers=headers)
    assert response.status_code == 401

def test_admin_only_endpoints(client, test_user_token, test_admin_token):
    """Test endpoints that require admin privileges."""
    # Try to list users with normal user token
    headers = {"Authorization": f"Bearer {test_user_token}"}
    response = client.get("/api/v1/users/", headers=headers)
    assert response.status_code == 403
    
    # List users with admin token
    headers = {"Authorization": f"Bearer {test_admin_token}"}
    response = client.get("/api/v1/users/", headers=headers)
    assert response.status_code == 200 