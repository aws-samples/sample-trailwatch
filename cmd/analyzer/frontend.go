package main

import "embed"

//go:embed dist/*
var frontendFS embed.FS
