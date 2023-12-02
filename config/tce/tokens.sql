-- Tokens

alter table tokens
add column encrypted_value text;

create or replace function public.tokens_encrypt_secret_value() returns "trigger"
    language "plpgsql"
    as $$
    begin
            new.encrypted_value = case when new.encrypted_value is null then null else
      case when '1492541a-a585-409f-ab51-f745e4858d46' is null then null else pg_catalog.encode(
        pgsodium.crypto_aead_det_encrypt(
        pg_catalog.convert_to(new.encrypted_value, 'utf8'),
        pg_catalog.convert_to(('')::text, 'utf8'),
        '1492541a-a585-409f-ab51-f745e4858d46'::uuid,
        null
        ),
        'base64') end end;
    return new;
    end;
$$;

alter function public.tokens_encrypt_secret_value() owner to "postgres";

grant all on function public.tokens_encrypt_secret_value() to "anon";
grant all on function public.tokens_encrypt_secret_value() to "authenticated";
grant all on function public.tokens_encrypt_secret_value() to "service_role";

create trigger tokens_encrypt_secret_trigger_value before insert or update of encrypted_value on public.tokens for each row execute function public.tokens_encrypt_secret_value();

create or replace view public.decrypted_tokens as
 select tokens.id,
    tokens.inserted_at,
    tokens.project_id,
    tokens.encrypted_value,
    tokens.created_by,
        case
            when (tokens.encrypted_value is null) then null::"text"
            else
            case
                when ('1492541a-a585-409f-ab51-f745e4858d46' is null) then null::"text"
                else convert_from(pgsodium.crypto_aead_det_decrypt(decode(tokens.encrypted_value, 'base64'::"text"), convert_to(''::"text", 'utf8'::"name"), '1492541a-a585-409f-ab51-f745e4858d46'::"uuid", null::"bytea"), 'utf8'::"name")
            end
        end as decrypted_value
   from public.tokens;

alter table public.decrypted_tokens owner to postgres;

security label for pgsodium on column public.tokens.encrypted_value is 'encrypt with key id 1492541a-a585-409f-ab51-f745e4858d46 security invoker';

update tokens
set encrypted_value = value
