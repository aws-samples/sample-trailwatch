package logviewer

import (
	"net/http"
	"os"
	"path/filepath"

	"cloudtrail-analyzer/internal/config"
	"cloudtrail-analyzer/internal/render"

	"github.com/go-chi/chi/v5"
)

// FileNode represents a file or directory in the tree.
type FileNode struct {
	Name     string     `json:"name"`
	Path     string     `json:"path"`
	IsDir    bool       `json:"is_dir"`
	Size     int64      `json:"size"`
	Children []FileNode `json:"children,omitempty"`
}

// Handler provides HTTP handlers for log viewer endpoints.
type Handler struct {
	cfg *config.Config
}

// NewHandler creates a new logviewer Handler.
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{cfg: cfg}
}

// Routes returns a Chi router with logviewer routes.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/sessions", h.GetFileTree)
	return r
}

// GetFileTree returns the file tree of the data/s3/ directory.
func (h *Handler) GetFileTree(w http.ResponseWriter, r *http.Request) {
	s3Dir := filepath.Join(h.cfg.DataDir, "s3")

	// Check if directory exists
	if _, err := os.Stat(s3Dir); os.IsNotExist(err) {
		render.JSON(w, http.StatusOK, []FileNode{})
		return
	}

	tree := buildTree(s3Dir, s3Dir, 0, 12)
	render.JSON(w, http.StatusOK, tree)
}

// buildTree recursively builds a file tree up to maxDepth levels.
func buildTree(basePath, currentPath string, depth, maxDepth int) []FileNode {
	if depth >= maxDepth {
		return nil
	}

	entries, err := os.ReadDir(currentPath)
	if err != nil {
		return nil
	}

	var nodes []FileNode
	for _, entry := range entries {
		fullPath := filepath.Join(currentPath, entry.Name())
		relPath, _ := filepath.Rel(basePath, fullPath)

		node := FileNode{
			Name:  entry.Name(),
			Path:  filepath.Join("data/s3", relPath),
			IsDir: entry.IsDir(),
		}

		if entry.IsDir() {
			node.Children = buildTree(basePath, fullPath, depth+1, maxDepth)
		} else {
			info, err := entry.Info()
			if err == nil {
				node.Size = info.Size()
			}
		}

		nodes = append(nodes, node)
	}

	return nodes
}
