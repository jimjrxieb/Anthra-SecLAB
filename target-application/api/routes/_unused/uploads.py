# data-dev:api-uploads-route
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel, AnyHttpUrl
import settings
import os
import uuid
import shutil
import imghdr

router = APIRouter(prefix="/api", tags=["uploads"])


class UploadResponse(BaseModel):
    url: AnyHttpUrl


def _public_upload_url(local_path: str) -> str:
    rel = os.path.relpath(local_path, settings.DATA_DIR).replace(os.path.sep, "/")
    return f"{settings.PUBLIC_BASE_URL}/{rel}"


@router.post("/upload/image", response_model=UploadResponse)
async def upload_image(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    # Write to /data/uploads/images/{uuid}_{sanitized-name}
    out_dir = os.path.join(settings.DATA_DIR, "uploads", "images")
    os.makedirs(out_dir, exist_ok=True)
    uid = uuid.uuid4().hex
    safe_name = "".join(
        c for c in file.filename if c.isalnum() or c in (".", "_", "-")
    )[:100]
    out_path = os.path.join(out_dir, f"{uid}_{safe_name}")

    with open(out_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # quick content sniff
    kind = imghdr.what(out_path)
    if kind not in {"png", "jpeg", "gif", "webp"}:
        os.remove(out_path)
        raise HTTPException(status_code=400, detail="Unsupported image type")

    return {"url": _public_upload_url(out_path)}
