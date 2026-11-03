-- A minimal sample table demonstrating SQLx migrations.
-- Replace with application-specific modules as the project evolves.
CREATE TABLE examples (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
