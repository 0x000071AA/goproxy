package main

type HttpResponse struct {
	message string `json:"message"`
	status  int    `json:"status"`
}

func HttpCreated(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  201,
	}
}

func HttpGet(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  200,
	}
}

func HttpBadRequest(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  400,
	}
}

func HttpDeleted(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  204,
	}
}

func HttpUpdated(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  200,
	}
}

func HttpInternalServerError(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  500,
	}
}

func HttpNotFound(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  404,
	}
}

func HttpAlreadyExists(msg string) *HttpResponse {
	return &HttpResponse{
		message: msg,
		status:  201,
	}
}
