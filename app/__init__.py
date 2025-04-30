from app.models import User, Doctor

@login_manager.user_loader
def load_user(user_id):
    # Try loading from both User and Doctor models
    user = User.query.get(int(user_id))
    if user:
        return user
    return Doctor.query.get(int(user_id))
