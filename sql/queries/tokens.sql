-- name: CreateToken :one
INSERT INTO refresh_tokens (token, user_id, created_at, updated_at, expires_at, revoked_at)
VALUES (
    $1,                -- token
    $2,                -- user_id
    NOW(),            -- created_at
    NOW(),            -- updated_at
    $3,               -- expires_at
    $4                 -- revoked_at (nullable)

)
RETURNING *;

-- name: RetrieveToken :one
SELECT * FROM refresh_tokens
WHERE token = $1
  AND revoked_at IS NULL;


-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(),
    updated_at = NOW()
WHERE token = $1;