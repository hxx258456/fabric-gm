/*
Copyright IBM Corp All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fakes

import http "github.com/hxx258456/ccgo/gmhttp"

type Handler struct {
	Code int
	Text string
}

func (h *Handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	resp.WriteHeader(h.Code)
	resp.Write([]byte(h.Text))
}
