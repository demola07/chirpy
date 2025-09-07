-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    gen_random_uuid(), -- id
    NOW(),             -- created_at
    NOW(),             -- updated_at
    $1                 -- email
)
RETURNING *;


-- name: DeleteAllUsers :exec
DELETE FROM users;