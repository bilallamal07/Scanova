const API_BASE = "http://localhost:8000";

/**
 * Browser File Scanner API Service
 * 
 * Provides methods to:
 * - Scan file:// URLs and local paths
 * - Browse local directories
 * - Upload files via drag-and-drop
 * - Find skill files in directories
 */

export const FileBrowserAPI = {
  /**
   * Parse and validate a file URL without scanning
   */
  async parseFileUrl(url) {
    const res = await fetch(`${API_BASE}/api/parse-file-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    
    if (!res.ok) {
      const error = await res.text();
      throw new Error(error);
    }
    
    return res.json();
  },

  /**
   * Scan a file:// URL or local path
   */
  async scanFileUrl(url) {
    const res = await fetch(`${API_BASE}/api/scan/file-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    
    if (!res.ok) {
      const error = await res.text();
      throw new Error(error);
    }
    
    return res.json();
  },

  /**
   * List directory contents
   */
  async listDirectory(path, pattern = "*", includeHidden = false) {
    const res = await fetch(`${API_BASE}/api/directory/list`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, pattern, include_hidden: includeHidden }),
    });
    
    if (!res.ok) {
      const error = await res.text();
      throw new Error(error);
    }
    
    return res.json();
  },

  /**
   * Get directory tree structure
   */
  async getDirectoryTree(path) {
    const res = await fetch(`${API_BASE}/api/directory/tree`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    
    if (!res.ok) {
      const error = await res.text();
      throw new Error(error);
    }
    
    return res.json();
  },

  /**
   * Find skill files in directory
   */
  async findSkills(path) {
    const res = await fetch(`${API_BASE}/api/directory/find-skills`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    });
    
    if (!res.ok) {
      const error = await res.text();
      throw new Error(error);
    }
    
    return res.json();
  },

  /**
   * Scan uploaded files (drag-and-drop)
   */
  async scanUploadedFiles(files) {
    const filesData = files.map(file => ({
      name: file.name,
      content: file.content,
      encoding: file.encoding || 'utf-8',
    }));

    const res = await fetch(`${API_BASE}/api/scan/upload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files: filesData }),
    });
    
    if (!res.ok) {
      const error = await res.text();
      throw new Error(error);
    }
    
    return res.json();
  },

  /**
   * Get common browser-accessible locations
   */
  async getBrowserLocations() {
    const res = await fetch(`${API_BASE}/api/browser/locations`);
    
    if (!res.ok) {
      const error = await res.text();
      throw new Error(error);
    }
    
    return res.json();
  },
};

/**
 * File utilities for browser file access
 */
export const FileUtils = {
  /**
   * Read a file as base64
   */
  async readAsBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const base64 = reader.result.split(',')[1];
        resolve(base64);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  },

  /**
   * Read a file as text
   */
  async readAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  },

  /**
   * Check if a string looks like a file URL or local path
   */
  isFileUrl(url) {
    const patterns = [
      /^file:\/\//,
      /^\/[A-Za-z0-9_./-]+/,
      /^[A-Za-z]:[/\\]/,
      /^~[/\\]/,
      /^[./]/,
    ];
    return patterns.some(pattern => pattern.test(url));
  },

  /**
   * Get file icon based on type
   */
  getFileIcon(filename, isDirectory = false) {
    if (isDirectory) return 'folder';
    
    const ext = filename.split('.').pop()?.toLowerCase();
    
    const iconMap = {
      'md': 'file-text',
      'py': 'file-code',
      'js': 'file-code',
      'ts': 'file-code',
      'json': 'file-json',
      'yaml': 'file-json',
      'yml': 'file-json',
      'txt': 'file-text',
      'sh': 'terminal',
      'bash': 'terminal',
    };
    
    return iconMap[ext] || 'file';
  },

  /**
   * Format file size
   */
  formatFileSize(bytes) {
    if (bytes === null || bytes === undefined) return '-';
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  },
};

export default FileBrowserAPI;