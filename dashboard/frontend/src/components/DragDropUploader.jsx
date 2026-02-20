import React, { useState, useCallback } from 'react';
import { Upload, File, X, Shield, AlertCircle } from 'lucide-react';
import { FileBrowserAPI, FileUtils } from '../services/fileBrowser';

export default function DragDropUploader({ onScanComplete, onClose }) {
  const [isDragging, setIsDragging] = useState(false);
  const [files, setFiles] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const droppedFiles = Array.from(e.dataTransfer.files);
    await processFiles(droppedFiles);
  }, []);

  const handleFileSelect = useCallback(async (e) => {
    const selectedFiles = Array.from(e.target.files);
    await processFiles(selectedFiles);
  }, []);

  const processFiles = async (fileList) => {
    setError(null);
    
    try {
      const processedFiles = await Promise.all(
        fileList.map(async (file) => {
          // Check if file is text or binary
          const isText = file.type.startsWith('text/') || 
                        file.name.endsWith('.md') ||
                        file.name.endsWith('.py') ||
                        file.name.endsWith('.js') ||
                        file.name.endsWith('.json') ||
                        file.name.endsWith('.yaml') ||
                        file.name.endsWith('.yml') ||
                        file.name.endsWith('.txt') ||
                        file.name.endsWith('.sh');

          if (isText) {
            const content = await FileUtils.readAsText(file);
            return {
              name: file.name,
              content: content,
              encoding: 'utf-8',
              size: file.size,
              type: file.type,
            };
          } else {
            const content = await FileUtils.readAsBase64(file);
            return {
              name: file.name,
              content: content,
              encoding: 'base64',
              size: file.size,
              type: file.type,
            };
          }
        })
      );

      setFiles(prev => [...prev, ...processedFiles]);
    } catch (err) {
      setError(`Failed to process files: ${err.message}`);
    }
  };

  const removeFile = (index) => {
    setFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleScan = async () => {
    if (files.length === 0) return;

    setScanning(true);
    setError(null);

    try {
      const report = await FileBrowserAPI.scanUploadedFiles(files);
      
      if (onScanComplete) {
        onScanComplete(report);
      }
    } catch (err) {
      setError(`Scan failed: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);

  return (
    <div className="drag-drop-uploader">
      {/* Header */}
      <div className="uploader-header">
        <div className="uploader-title">
          <Upload size={20} />
          <span>Upload & Scan Files</span>
        </div>
        {onClose && (
          <button className="uploader-close" onClick={onClose}>
            <X size={20} />
          </button>
        )}
      </div>

      {/* Drop Zone */}
      <div
        className={`drop-zone ${isDragging ? 'is-dragging' : ''} ${files.length > 0 ? 'has-files' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input
          type="file"
          multiple
          onChange={handleFileSelect}
          className="file-input"
          id="file-upload"
        />
        <label htmlFor="file-upload" className="drop-zone-label">
          <Upload size={48} className="drop-zone-icon" />
          <p className="drop-zone-text">
            <strong>Drop files here</strong> or click to browse
          </p>
          <p className="drop-zone-hint">
            Supports: .md, .py, .js, .json, .yaml, .txt, .sh
          </p>
        </label>
      </div>

      {/* Error */}
      {error && (
        <div className="uploader-error">
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* File List */}
      {files.length > 0 && (
        <div className="file-list">
          <div className="file-list-header">
            <span className="file-count">{files.length} file(s)</span>
            <span className="file-total-size">{FileUtils.formatFileSize(totalSize)}</span>
          </div>
          
          <div className="file-list-items">
            {files.map((file, index) => (
              <div key={index} className="file-list-item">
                <div className="file-info">
                  <File size={16} />
                  <span className="file-name" title={file.name}>
                    {file.name}
                  </span>
                  <span className="file-size">
                    {FileUtils.formatFileSize(file.size)}
                  </span>
                </div>
                <button 
                  className="file-remove"
                  onClick={() => removeFile(index)}
                  title="Remove file"
                >
                  <X size={14} />
                </button>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div className="file-list-actions">
            <button 
              className="btn btn-secondary"
              onClick={() => setFiles([])}
              disabled={scanning}
            >
              Clear All
            </button>
            <button 
              className="btn btn-primary"
              onClick={handleScan}
              disabled={scanning || files.length === 0}
            >
              {scanning ? (
                <>
                  <span className="spinner" />
                  Scanning...
                </>
              ) : (
                <>
                  <Shield size={16} />
                  Scan {files.length} File{files.length !== 1 ? 's' : ''}
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}