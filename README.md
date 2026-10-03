# Full-Stack App

A full-stack web application with React + Vite (frontend) and Node.js + Express + Prisma (backend) with PostgreSQL.

## Project Structure

```
sss/
├── backend/          # Express + TypeScript + Prisma
│   ├── src/
│   │   └── index.ts  # Main server entry
│   ├── prisma/
│   │   └── schema.prisma
│   ├── package.json
│   └── tsconfig.json
└── frontend/         # React + Vite + TypeScript
    ├── src/
    │   ├── App.tsx
    │   ├── main.tsx
    │   └── index.css
    ├── index.html
    ├── package.json
    ├── tsconfig.json
    └── vite.config.ts
```

## Prerequisites

- Node.js 18+
- PostgreSQL database

## Setup

### 1. Backend Setup

```bash
cd backend
cp .env.example .env
# Edit .env with your PostgreSQL connection string
npm install
npm run prisma:generate
npm run prisma:migrate
npm run dev
```

The backend runs on http://localhost:3001

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend runs on http://localhost:5173 (proxies API calls to backend)

## API Endpoints

- `GET /api/health` - Health check
- `GET /api/users` - List all users with posts
- `POST /api/users` - Create user
- `GET /api/posts` - List all posts with authors
- `POST /api/posts` - Create post
- `PATCH /api/posts/:id` - Update post
- `DELETE /api/posts/:id` - Delete post

## Database Models

- **User**: id, email, name, createdAt, updatedAt
- **Post**: id, title, content, published, authorId, createdAt, updatedAt

## Features

- Create, read, update, delete posts
- Create users
- Publish/unpublish posts
- Responsive UI with clean CSS
- Type-safe API calls
- Vite proxy for seamless dev experience