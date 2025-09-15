-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(), -- id
    NOW(),             -- created_at
    NOW(),             -- updated_at
    $1,                 -- email
    $2                -- hashed_password
)
RETURNING *;


-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: UpdateUser :one
UPDATE users
SET
    updated_at = NOW(),
    email = COALESCE(NULLIF(sqlc.arg(email), ''), email),
    hashed_password = COALESCE(NULLIF(sqlc.arg(hashed_password), ''), hashed_password)
WHERE id = sqlc.arg(id)
RETURNING *;