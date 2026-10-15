from fastapi import APIRouter, Depends, HTTPException

from app.models import User
from app.pipeline import process_flow
from app.schemas import PredictRequest, PredictResponse
from app.security import get_current_user

router = APIRouter(tags=["predict"])


@router.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest, _user: User = Depends(get_current_user)):
    result = process_flow(payload.model_dump(), persist_traffic=True)
    if "error" in result:
        raise HTTPException(status_code=503, detail="Models not trained yet. Run `python -m app.ml.train`.")
    return result
