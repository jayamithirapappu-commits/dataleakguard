from fastapi import APIRouter, HTTPException
from backend.models.schemas import ScanRequest, ScanResponse, HealthResponse, DetectedEntity
from backend.core.detector import SensitiveDataDetector

router = APIRouter()

# Initialize detector (singleton for the application)
detector = SensitiveDataDetector()


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    Returns the status of the DataLeakGuard service.
    """
    return HealthResponse(status="ok", service="DataLeakGuard")


@router.post("/api/scan", response_model=ScanResponse)
async def scan_prompt(request: ScanRequest):
    """
    Scan a prompt for sensitive data.
    
    This endpoint analyzes the text locally using Presidio Analyzer.
    The original prompt is NOT sent to any external AI model.
    
    Args:
        request: ScanRequest containing the prompt to analyze
        
    Returns:
        ScanResponse with detected entities and risk score
    """
    if not request.prompt or not request.prompt.strip():
        return ScanResponse(
            detected=[],
            risk_score=0,
            analysis_stage="sensitive_data_detection"
        )
    
    try:
        # Detect sensitive data locally
        detected_data = detector.detect(request.prompt)
        
        # Calculate overall risk score
        risk_score = detector.calculate_risk_score(detected_data)
        
        # Convert to response format
        detected_entities = [
            DetectedEntity(**entity) for entity in detected_data
        ]
        
        return ScanResponse(
            detected=detected_entities,
            risk_score=risk_score,
            analysis_stage="sensitive_data_detection"
        )
        
    except Exception as e:
        # Log error without exposing sensitive information
        # In production, use proper logging
        raise HTTPException(status_code=500, detail="Analysis failed")
