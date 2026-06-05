package vengtoo

import (
	"net/http"
)

// HTTPMiddleware returns a net/http middleware that checks authorization.
// subjectIDHeader is the header containing the subject ID (e.g., "X-User-ID").
func (c *Client) HTTPMiddleware(resourceType, action, subjectIDHeader string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subjectID := r.Header.Get(subjectIDHeader)
			if subjectID == "" {
				http.Error(w, `{"error":"missing subject ID"}`, http.StatusUnauthorized)
				return
			}

			allowed, err := c.Check(r.Context(),
				Subject{ID: subjectID, Type: "user"},
				action,
				Resource{Type: resourceType, ID: r.URL.Path},
			)
			if err != nil {
				http.Error(w, `{"error":"authorization check failed"}`, http.StatusInternalServerError)
				return
			}
			if !allowed {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// For Gin users — no gin dependency needed, just wrap Check() directly:
//
//	func AuthzMiddleware(client *vengtoo.Client, resourceType, action string) gin.HandlerFunc {
//	    return func(c *gin.Context) {
//	        allowed, err := client.Check(c.Request.Context(),
//	            vengtoo.Subject{ID: c.GetHeader("X-User-ID"), Type: "user"},
//	            action,
//	            vengtoo.Resource{Type: resourceType, ID: c.Param("id")},
//	        )
//	        if err != nil || !allowed {
//	            c.AbortWithStatusJSON(403, gin.H{"error": "forbidden"})
//	            return
//	        }
//	        c.Next()
//	    }
//	}
