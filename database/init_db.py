from database.db_manager import engine
from database.base import Base

# Import all models so they are registered with Base
from models.users import User
from models.agent_report import AgentReport
# Add other models as needed

def init_all_tables():
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    init_all_tables()