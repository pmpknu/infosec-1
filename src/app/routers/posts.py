import bleach
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.db import get_db
from app.security import get_current_user

router = APIRouter(prefix="/api/posts", tags=["posts"])


@router.get("", response_model=list[schemas.PostOut])
async def list_posts(
    db: Session = Depends(get_db),
    _: models.User = Depends(get_current_user),
):
    return db.query(models.Post).order_by(models.Post.created_at.desc()).all()


@router.post("", response_model=schemas.PostOut, status_code=status.HTTP_201_CREATED)
async def create_post(
    post_in: schemas.PostCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    sanitized_title = bleach.clean(post_in.title, strip=True)
    sanitized_content = bleach.clean(post_in.content, strip=True)

    if not sanitized_title.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Title removed by sanitizer"
        )
    if not sanitized_content.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Content removed by sanitizer"
        )

    post = models.Post(
        title=sanitized_title,
        content=sanitized_content,
        owner_id=current_user.id,
    )
    db.add(post)
    db.commit()
    db.refresh(post)
    return post
