package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func JSONResponse(writer http.ResponseWriter, data interface{}, statusCode int) {
	JSONData, err := json.Marshal(data)

	if err != nil {
		http.Error(writer, "Error creating JSON response", http.StatusInternalServerError)
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(statusCode)
	fmt.Fprintf(writer, "%s", JSONData)
}
