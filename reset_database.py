#!/usr/bin/env python3
"""
Reset database and create fresh admin user
"""

import os
from app import Base, engine, create_super_admin, create_standard_departments

def reset_database():
    """Reset the entire database"""
    try:
        # Remove existing database file
        if os.path.exists("hms.db"):
            os.remove("hms.db")
            print("🗑️  Removed existing database")
        
        # Create fresh database
        print("🔨 Creating fresh database...")
        Base.metadata.create_all(engine)
        
        # Create super admin
        print("👤 Creating super admin...")
        create_super_admin()
        
        # Create departments
        print("🏥 Creating departments...")
        create_standard_departments()
        
        print("✅ Database reset complete!")
        print("\nDefault admin credentials:")
        print("Username: admin")
        print("Password: admin123")
        
    except Exception as e:
        print(f"❌ Error resetting database: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "confirm":
        reset_database()
    else:
        print("⚠️  This will DELETE ALL DATA in the database!")
        print("To confirm, run: python reset_database.py confirm")