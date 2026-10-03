import { useState, useEffect } from 'react';

interface User {
  id: string;
  email: string;
  name: string | null;
  createdAt: string;
  posts: Post[];
}

interface Post {
  id: string;
  title: string;
  content: string | null;
  published: boolean;
  authorId: string;
  author: User;
  createdAt: string;
  updatedAt: string;
}

const API_BASE = '/api';

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

function App() {
  const [users, setUsers] = useState<User[]>([]);
  const [posts, setPosts] = useState<Post[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'users' | 'posts'>('posts');
  const [showUserForm, setShowUserForm] = useState(false);
  const [showPostForm, setShowPostForm] = useState(false);
  const [editingPost, setEditingPost] = useState<Post | null>(null);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [usersData, postsData] = await Promise.all([
        fetchApi<User[]>('/users'),
        fetchApi<Post[]>('/posts')
      ]);
      setUsers(usersData);
      setPosts(postsData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreateUser = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    try {
      await fetchApi('/users', {
        method: 'POST',
        body: JSON.stringify({
          email: formData.get('email'),
          name: formData.get('name')
        })
      });
      setShowUserForm(false);
      (e.target as HTMLFormElement).reset();
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user');
    }
  };

  const handleCreatePost = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const formData = new FormData(e.currentTarget);
    try {
      if (editingPost) {
        await fetchApi(`/posts/${editingPost.id}`, {
          method: 'PATCH',
          body: JSON.stringify({
            title: formData.get('title'),
            content: formData.get('content'),
            published: formData.get('published') === 'on'
          })
        });
        setEditingPost(null);
      } else {
        await fetchApi('/posts', {
          method: 'POST',
          body: JSON.stringify({
            title: formData.get('title'),
            content: formData.get('content'),
            authorId: formData.get('authorId')
          })
        });
      }
      setShowPostForm(false);
      (e.target as HTMLFormElement).reset();
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save post');
    }
  };

  const handleDeletePost = async (id: string) => {
    if (!confirm('Delete this post?')) return;
    try {
      await fetchApi(`/posts/${id}`, { method: 'DELETE' });
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete post');
    }
  };

  const handleTogglePublish = async (post: Post) => {
    try {
      await fetchApi(`/posts/${post.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ published: !post.published })
      });
      loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update post');
    }
  };

  if (loading) return <div className="loading">Loading...</div>;

  return (
    <div className="container">
      <h1>Full-Stack App</h1>
      
      {error && <div className="error">{error}</div>}

      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
        <button 
          className={`btn ${activeTab === 'posts' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('posts')}
        >
          Posts
        </button>
        <button 
          className={`btn ${activeTab === 'users' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('users')}
        >
          Users
        </button>
      </div>

      {activeTab === 'posts' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2>Posts</h2>
            <button className="btn btn-primary" onClick={() => { setEditingPost(null); setShowPostForm(true); }}>
              New Post
            </button>
          </div>

          {showPostForm && (
            <div className="card">
              <h3>{editingPost ? 'Edit Post' : 'New Post'}</h3>
              <form onSubmit={handleCreatePost}>
                <div className="form-group">
                  <label>Title</label>
                  <input name="title" required defaultValue={editingPost?.title || ''} />
                </div>
                <div className="form-group">
                  <label>Content</label>
                  <textarea name="content" rows={4} defaultValue={editingPost?.content || ''} />
                </div>
                <div className="form-group">
                  <label>Author</label>
                  <select name="authorId" required defaultValue={editingPost?.authorId || ''} disabled={!!editingPost}>
                    <option value="">Select author</option>
                    {users.map(u => (
                      <option key={u.id} value={u.id}>{u.name || u.email}</option>
                    ))}
                  </select>
                </div>
                {editingPost && (
                  <div className="form-group">
                    <label>
                      <input type="checkbox" name="published" defaultChecked={editingPost.published} />
                      Published
                    </label>
                  </div>
                )}
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button type="submit" className="btn btn-primary">{editingPost ? 'Update' : 'Create'}</button>
                  <button type="button" className="btn btn-secondary" onClick={() => { setShowPostForm(false); setEditingPost(null); }}>Cancel</button>
                </div>
              </form>
            </div>
          )}

          <div className="post-list">
            {posts.length === 0 ? (
              <div className="card">No posts yet. Create one!</div>
            ) : (
              posts.map(post => (
                <div key={post.id} className="card post-item">
                  <div className="post-content">
                    <h3>{post.title}</h3>
                    {post.content && <p>{post.content}</p>}
                    <div className="post-meta">
                      By {post.author.name || post.author.email} • {new Date(post.createdAt).toLocaleDateString()}
                      {' • '}{post.published ? 'Published' : 'Draft'}
                    </div>
                  </div>
                  <div className="post-actions">
                    {!editingPost && (
                      <>
                        <button className="btn btn-primary" onClick={() => setEditingPost(post)}>Edit</button>
                        <button className="btn btn-danger" onClick={() => handleDeletePost(post.id)}>Delete</button>
                        <button className="btn btn-secondary" onClick={() => handleTogglePublish(post)}>
                          {post.published ? 'Unpublish' : 'Publish'}
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </>
      )}

      {activeTab === 'users' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2>Users</h2>
            <button className="btn btn-primary" onClick={() => setShowUserForm(true)}>New User</button>
          </div>

          {showUserForm && (
            <div className="card">
              <h3>New User</h3>
              <form onSubmit={handleCreateUser}>
                <div className="form-group">
                  <label>Email</label>
                  <input name="email" type="email" required />
                </div>
                <div className="form-group">
                  <label>Name (optional)</label>
                  <input name="name" />
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button type="submit" className="btn btn-primary">Create</button>
                  <button type="button" className="btn btn-secondary" onClick={() => setShowUserForm(false)}>Cancel</button>
                </div>
              </form>
            </div>
          )}

          <div className="post-list">
            {users.length === 0 ? (
              <div className="card">No users yet. Create one!</div>
            ) : (
              users.map(user => (
                <div key={user.id} className="card">
                  <h3>{user.name || 'Unnamed'}</h3>
                  <p>{user.email}</p>
                  <div className="post-meta">
                    {user.posts.length} post(s) • Created {new Date(user.createdAt).toLocaleDateString()}
                  </div>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default App;