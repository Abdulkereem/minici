# Minici

Minici is a lightweight Continuous Integration/Continuous Deployment (CI/CD) tool designed for solo developers or smaller projects that need basic CI/CD with a VPS server. If you require a more robust solution for larger projects, you may want to explore tools like Jenkins.

## Features

- Register projects with name, directory, and deploy commands
- View a dashboard of registered projects
- Trigger deployments to production
- Rebuild projects
- Run custom commands

## Backend Code Overview

The backend of Minici is built using Flask, a popular Python web framework. It uses Flask SQLAlchemy for database management and subprocess for executing commands. The main components of the backend code include `minici.py` and `projects.db`.

## Frontend Code Overview

The frontend of Minici is built using HTML, CSS (with the Tailwind CSS framework), and JavaScript (with the jQuery library). The main components of the frontend code include `dashboard.html`, `register.html`, `main.css`, and `jquery.min.js`.

## Prerequisites

- Python 3.9 or higher
- Pip package manager
- Git

## Installation

1. Clone the Minici repository:
   ```shell
   git clone https://github.com/your-username/minici.git
   cd minici
   pip install -r requirements.txt

   
## Usage
