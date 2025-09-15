-- name: CreateChirpy :one
INSERT INTO chirpy (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(), -- id
    NOW(),             -- created_at
    NOW(),             -- updated_at
    $1,                 -- body
    $2                 -- user_id
)
RETURNING *;

-- name: DeleteAllChirpy :exec
DELETE FROM chirpy;

-- name: ListChirpy :many
SELECT * FROM chirpy
ORDER BY created_at ASC;

-- name: GetChirpyByID :one
SELECT * FROM chirpy
WHERE id = $1;

-- name: DeleteChirpyByID :exec
DELETE FROM chirpy
WHERE id = $1 AND user_id = $2;