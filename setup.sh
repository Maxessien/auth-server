#!/bin/bash

# Set the database URL environment variable
export DATABASE_URL="<DATABASE_URL>"

# Run the initialization binary
cargo run --bin init_tables

# Check the project for errors
cargo check
