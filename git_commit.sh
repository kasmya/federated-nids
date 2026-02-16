#!/bin/bash
# Git Commit Helper - Easy commits for NIDS project

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "  NIDS Git Commit Helper"
echo "========================================="

# Check if git is initialized
if [ ! -d .git ]; then
    echo -e "${YELLOW}Initializing git repository...${NC}"
    git init
fi

# Show status
echo ""
echo "Current status:"
git status --short

# Get commit message
if [ -z "$1" ]; then
    echo ""
    echo "Usage: ./git_commit.sh \"Your commit message\""
    echo "Or run interactively:"
    read -p "Enter commit message: " msg
else
    msg="$1"
fi

if [ -z "$msg" ]; then
    echo -e "${YELLOW}No commit message provided. Aborting.${NC}"
    exit 1
fi

# Add all changes
echo ""
echo -e "${GREEN}Adding changes...${NC}"
git add -A

# Show what will be committed
echo ""
echo "Files to commit:"
git diff --cached --name-only

# Commit
echo ""
echo -e "${GREEN}Committing...${NC}"
git commit -m "$msg"

# Show result
echo ""
echo "========================================="
echo -e "${GREEN}Committed successfully!${NC}"
echo "========================================="
echo ""
echo "To push to GitHub:"
echo "  git push origin main"
echo ""

