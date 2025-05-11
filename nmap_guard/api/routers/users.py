"""
Router for user management.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime

from ...db.models import User
from ..schemas import UserCreate, UserResponse
from ..dependencies import (
    get_db, get_current_active_user, get_admin_user,
    get_password_hash, verify_password
)

router = APIRouter()

@router.post("/", response_model=UserResponse)
async def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)  # Only admins can create users
):
    """Create a new user."""
    # Check if username exists
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
        
    # Check if email exists
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
        
    # Create user
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password),
        is_active=user.is_active
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

@router.get("/", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)  # Only admins can list users
):
    """List users."""
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get user details."""
    # Users can view their own details, admins can view any user
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to access this user")
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    return user

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update user details."""
    # Users can update their own details, admins can update any user
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to modify this user")
        
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Check username uniqueness if changed
    if user_update.username != db_user.username:
        if db.query(User).filter(User.username == user_update.username).first():
            raise HTTPException(status_code=400, detail="Username already taken")
            
    # Check email uniqueness if changed
    if user_update.email != db_user.email:
        if db.query(User).filter(User.email == user_update.email).first():
            raise HTTPException(status_code=400, detail="Email already registered")
            
    # Update fields
    db_user.username = user_update.username
    db_user.email = user_update.email
    db_user.hashed_password = get_password_hash(user_update.password)
    db_user.is_active = user_update.is_active
    
    db.commit()
    db.refresh(db_user)
    
    return db_user

@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)  # Only admins can delete users
):
    """Delete a user."""
    # Prevent deleting the last admin
    if user_id == current_user.id:
        admin_count = db.query(User).filter(User.is_admin == True).count()
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last admin user"
            )
            
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Check if user has associated data
    if user.scan_configs or user.scans:
        # Soft delete by deactivating
        user.is_active = False
        db.commit()
        return {"message": "User deactivated"}
    else:
        # Hard delete if no associated data
        db.delete(user)
        db.commit()
        return {"message": "User deleted"}

@router.post("/{user_id}/change-password")
async def change_password(
    user_id: int,
    old_password: str,
    new_password: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Change user password."""
    # Users can change their own password, admins can change any user's password
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to change this user's password")
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Verify old password (skip for admins changing other users' passwords)
    if user_id == current_user.id and not verify_password(old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")
        
    # Update password
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    
    return {"message": "Password updated successfully"}

@router.post("/{user_id}/toggle-admin")
async def toggle_admin_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_admin_user)  # Only admins can modify admin status
):
    """Toggle user's admin status."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot modify your own admin status")
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Toggle admin status
    user.is_admin = not user.is_admin
    db.commit()
    
    return {
        "message": f"User is {'now' if user.is_admin else 'no longer'} an admin"
    } 