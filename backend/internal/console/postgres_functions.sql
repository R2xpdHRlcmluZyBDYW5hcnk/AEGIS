CREATE OR REPLACE FUNCTION aegis.hunt_fold(value text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT lower(value) $$;

CREATE OR REPLACE FUNCTION aegis.hunt_network(value text, prefix text) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
SELECT CASE WHEN pg_input_is_valid(value,'inet') AND pg_input_is_valid(prefix,'cidr')
THEN value::inet <<= prefix::cidr ELSE false END $$;

CREATE OR REPLACE FUNCTION aegis.hunt_glob(value text, pattern text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE expression text := '^'; i integer := 1; j integer; c text; content text;
BEGIN
  WHILE i <= char_length(pattern) LOOP
    c := substr(pattern,i,1);
    IF c = chr(92) THEN
      i := i+1; c := CASE WHEN i>char_length(pattern) THEN chr(92) ELSE substr(pattern,i,1) END;
      IF strpos(E'\\.^$|()[]{}*+?',c)>0 THEN expression:=expression||chr(92); END IF;
      expression:=expression||c;
    ELSIF c='*' THEN expression:=expression||'.*';
    ELSIF c='?' THEN expression:=expression||'.';
    ELSIF c='[' THEN
      j:=i+1; WHILE j<=char_length(pattern) AND substr(pattern,j,1)<>']' LOOP j:=j+1; END LOOP;
      IF j<=char_length(pattern) THEN
        content:=substr(pattern,i+1,j-i-1);
        IF left(content,1)='!' THEN content:='^'||substr(content,2); END IF;
        expression:=expression||'['||content||']'; i:=j;
      ELSE expression:=expression||chr(92)||'['; END IF;
    ELSE
      IF strpos(E'\\.^$|()[]{}*+?',c)>0 THEN expression:=expression||chr(92); END IF;
      expression:=expression||c;
    END IF;
    i:=i+1;
  END LOOP;
  RETURN value ~ (expression||'$');
EXCEPTION WHEN invalid_regular_expression THEN RETURN false;
END $$;

CREATE OR REPLACE FUNCTION aegis.hunt_metadata(data jsonb, field text, query text, icase boolean) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE item text; needle text := query; substring_match boolean := right(field,5)='_name';
BEGIN
  IF data IS NULL OR NOT data ? field THEN RETURN false; END IF;
  IF query='*' THEN RETURN jsonb_array_length(data->field)>0; END IF;
  IF icase OR right(field,3)='_id' THEN needle:=lower(needle); END IF;
  FOR item IN SELECT jsonb_array_elements_text(data->field) LOOP
    IF icase OR right(field,3)='_id' THEN item:=lower(item); END IF;
    IF strpos(needle,'*')>0 OR strpos(needle,'?')>0 THEN
      IF aegis.hunt_glob(item,CASE WHEN substring_match THEN '*'||needle||'*' ELSE needle END) THEN RETURN true; END IF;
    ELSIF substring_match THEN IF strpos(item,needle)>0 THEN RETURN true; END IF;
    ELSIF item=needle THEN RETURN true;
    END IF;
  END LOOP;
  RETURN false;
END $$;
