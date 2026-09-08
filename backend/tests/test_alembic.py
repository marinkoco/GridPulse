from pathlib import Path
from alembic.config import Config
from alembic.script import ScriptDirectory
from app.config import settings

def test_alembic_config_and_script_directory():
    ini_path = Path(__file__).resolve().parent.parent / "alembic.ini"
    assert ini_path.exists()
    
    alembic_cfg = Config(str(ini_path))
    script = ScriptDirectory.from_config(alembic_cfg)
    assert script is not None
    assert script.dir is not None

def test_database_settings_url():
    assert "postgresql+asyncpg://" in settings.async_database_url
    assert "postgresql://" in settings.sync_database_url
