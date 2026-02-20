import React, { useState, useEffect, useCallback } from 'react';
import { 
  Folder, 
  File, 
  FileText, 
  FileCode, 
  FileJson, 
  Terminal,
  ChevronRight,
  ChevronDown,
  ArrowUp,
  RefreshCw,
  Search,
  Shield,
  X
} from 'lucide-react';
import { FileBrowserAPI, FileUtils } from '../services/fileBrowser';

const FILE_ICONS = {
  folder: Folder,
  file: File,
  'file-text': FileText,
  'file-code': FileCode,
  'file-json': FileJson,
  terminal: Terminal,
};

export default function FileBrowser({ 
  initialPath = '', 
  onSelect,
  onScan,
  onClose,
  showScanButton = true 
}) {
  const [currentPath, setCurrentPath] = useState(initialPath);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [breadcrumbs, setBreadcrumbs] = useState([]);
  const [browserLocations, setBrowserLocations] = useState({});

  // Load browser locations on mount
  useEffect(() => {
    loadBrowserLocations();
  }, []);

  // Load directory contents when path changes
  useEffect(() => {
    if (currentPath) {
      loadDirectory(currentPath);
    }
  }, [currentPath]);

  const loadBrowserLocations = async () => {
    try {
      const locations = await FileBrowserAPI.getBrowserLocations();
      setBrowserLocations(locations);
      // Set default path if none provided
      if (!initialPath && locations.home) {
        setCurrentPath(locations.home);
      }
    } catch (err) {
      console.error('Failed to load browser locations:', err);
    }
  };

  const loadDirectory = async (path) => {
    setLoading(true);
    setError(null);
    
    try {
      const data = await FileBrowserAPI.listDirectory(path);
      setItems(data.items);
      updateBreadcrumbs(path);
    } catch (err) {
      setError(err.message);
      setItems([]);
    } finally {
      setLoading(false);
    }
  };

  const updateBreadcrumbs = (path) => {
    const parts = path.split('/').filter(Boolean);
    const crumbs = parts.map((part, index) => {
      const pathUpTo = '/' + parts.slice(0, index + 1).join('/');
      return { name: part, path: pathUpTo };
    });
    setBreadcrumbs(crumbs);
  };

  const handleItemClick = (item) => {
    if (item.is_directory) {
      setCurrentPath(item.path);
    } else {
      // Select file
      if (onSelect) {
        onSelect(item);
      }
    }
  };

  const handleNavigateUp = () => {
    const parent = currentPath.split('/').slice(0, -1).join('/') || '/';
    setCurrentPath(parent);
  };

  const handleBreadcrumbClick = (path) => {
    setCurrentPath(path);
  };

  const handleScanCurrent = () => {
    if (onScan) {
      onScan(currentPath);
    }
  };

  const handleScanItem = (item) => {
    if (onScan) {
      onScan(item.path);
    }
  };

  const filteredItems = items.filter(item => 
    item.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getIcon = (item) => {
    const iconName = FileUtils.getFileIcon(item.name, item.is_directory);
    const IconComponent = FILE_ICONS[iconName] || File;
    return <IconComponent size={20} />;
  };

  return (
    <div className="file-browser">
      {/* Header */}
      <div className="file-browser-header">
        <div className="file-browser-title">
          <Folder size={20} />
          <span>File Browser</span>
        </div>
        {onClose && (
          <button className="file-browser-close" onClick={onClose}>
            <X size={20} />
          </button>
        )}
      </div>

      {/* Toolbar */}
      <div className="file-browser-toolbar">
        <button 
          className="toolbar-btn" 
          onClick={handleNavigateUp}
          disabled={currentPath === '/'}
        >
          <ArrowUp size={16} />
          Up
        </button>
        
        <button 
          className="toolbar-btn" 
          onClick={() => loadDirectory(currentPath)}
        >
          <RefreshCw size={16} />
          Refresh
        </button>

        <div className="toolbar-search">
          <Search size={16} />
          <input
            type="text"
            placeholder="Search files..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        {showScanButton && (
          <button 
            className="toolbar-btn toolbar-btn-primary"
            onClick={handleScanCurrent}
          >
            <Shield size={16} />
            Scan Directory
          </button>
        )}
      </div>

      {/* Breadcrumbs */}
      <div className="file-browser-breadcrumbs">
        <span className="breadcrumb-root" onClick={() => setCurrentPath('/')}>
          /
        </span>
        {breadcrumbs.map((crumb, index) => (
          <React.Fragment key={crumb.path}>
            <ChevronRight size={14} className="breadcrumb-separator" />
            <span 
              className="breadcrumb-item"
              onClick={() => handleBreadcrumbClick(crumb.path)}
            >
              {crumb.name}
            </span>
          </React.Fragment>
        ))}
      </div>

      {/* Quick Locations */}
      {Object.keys(browserLocations).length > 0 && (
        <div className="file-browser-locations">
          <span className="locations-label">Quick access:</span>
          {Object.entries(browserLocations).map(([name, path]) => (
            <button
              key={name}
              className="location-btn"
              onClick={() => setCurrentPath(path)}
            >
              {name.charAt(0).toUpperCase() + name.slice(1)}
            </button>
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="file-browser-error">
          {error}
        </div>
      )}

      {/* File List */}
      <div className="file-browser-list">
        {loading ? (
          <div className="file-browser-loading">
            <RefreshCw className="animate-spin" size={24} />
            <span>Loading...</span>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="file-browser-empty">
            {searchTerm ? 'No files match your search' : 'Directory is empty'}
          </div>
        ) : (
          <table className="file-browser-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Size</th>
                {showScanButton && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {filteredItems.map((item) => (
                <tr 
                  key={item.path}
                  className={item.is_directory ? 'is-directory' : ''}
                  onClick={() => handleItemClick(item)}
                >
                  <td className="file-name">
                    {getIcon(item)}
                    <span>{item.name}</span>
                  </td>
                  <td className="file-type">
                    {item.is_directory ? 'Directory' : 'File'}
                  </td>
                  <td className="file-size">
                    {FileUtils.formatFileSize(item.size)}
                  </td>
                  {showScanButton && (
                    <td className="file-actions">
                      {item.is_directory && (
                        <button
                          className="action-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleScanItem(item);
                          }}
                        >
                          <Shield size={14} />
                          Scan
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Current Path Display */}
      <div className="file-browser-path">
        <span className="path-label">Current path:</span>
        <code className="path-value">{currentPath}</code>
      </div>
    </div>
  );
}