:- use_module(library(http/thread_httpd)).
:- use_module(library(http/http_dispatch)).
:- use_module(library(http/http_parameters)).
:- use_module(library(http/http_session)).
:- use_module(library(http/http_client)).
:- use_module(library(http/http_header)).
:- use_module(library(http/json)).
:- use_module(library(http/http_json)).
:- use_module(library(http/http_path)).
:- use_module(library(crypto)).
:- use_module(library(uri)).
:- use_module(library(pio)).
:- use_module(library(odbc)).
:- use_module(library(pcre)).
:- use_module(library(dicts)).
:- use_module(library(lists)).
% :- use_module(library(clpfd)).
:- use_module(database, [query/2, query/3, fetch_all/2, fetch_all/3, enable_transactions/0, commit/0, rollback/0, get_connection/1]).

:- expects_dialect(sicstus).

:- set_prolog_flag(report_error, true).
:- set_prolog_flag(unknown, error).
:- set_prolog_flag(re_compile, true).


csrf_cookie('CSRF-Token').

http_exception(Message, Code).
http_exception(Message, Data, Code).



http_cookie_value(Request, Name, Value) :-
    memberchk(cookie(CookieList), Request),
    nth1(_, CookieList, Name=Value).



user_is_logged :-
    http_session_data(user_id(_)) ; false.


logged_user_id(Id) :-
    http_session_data(user_id(Id)).


server(Port) :-
    http_server(http_dispatch, [port(Port)]).

:- http_handler('/login', login, [ methods([post]) ]).
:- http_handler('/logout', logout, [ methods([post]) ]).
:- http_handler('/registration', registration, [ methods([post]) ]).
:- http_handler(root('api/note'), notes_action, [ methods([get, post, put, delete]), prefix ]).
:- http_handler('/', render_index_view, [ method(get) ]).



render_index_view(_Request) :-
    catch(
        (
            init_conn,
            http_clean_location_cache,
            % Delete expired tokens in database
            (   query('DELETE FROM token WHERE expiry < (SELECT EXTRACT(EPOCH FROM NOW()))', _) 
            ;   true
            ),
            % Create CSRF token and store it in database
            crypto_n_random_bytes(40, Bytes),
            hex_bytes(CsrfTokenValue, Bytes),
            get_time(Time),
            TimeInSeconds is round(Time) + 1200,
            (   query('INSERT INTO token (value, type, expiry) VALUES(?, ?, ?)', [CsrfTokenValue, csrf_token, TimeInSeconds], _)
            ;   throw(error('Internal server error.'))
            ),
            close_conn,
            % Send response
            csrf_cookie(CookieName),
            format('Content-type: text/html~n'),
            format('Set-Cookie: ~w=~w; HttpOnly~n~n', [CookieName, CsrfTokenValue]),
            print_file_contents('views/index.html')
        ),
        error(_, Ctx),
        (   close_conn
        ,   throw(error('Internal server error.', Ctx))
        )
    ).



check_csrf(Request) :-
    csrf_cookie(CookieName),
    http_cookie_value(Request, CookieName, CsrfToken),
    get_time(Time),
    TimeInSeconds is round(Time),
    query('SELECT id FROM token WHERE value = ? AND expiry >= ?', [CsrfToken, TimeInSeconds], _).



login(Request) :-
    catch(
        (
            init_conn,
            (   not(user_is_logged) 
            ;   throw(http_exception('Forbidden.', 403))
            ),
            % (   check_csrf(Request) 
            % ;   throw(http_exception('Invalid CSRF token.', 400))
            % ),
            (   http_read_json_dict(Request, Dict) 
            ;   throw(http_exception('Invalid content.', 400))
            ),
            (   get_dict(email, Dict, Email) 
            ;   throw(http_exception('Missing email.', 400))
            ),
            (   get_dict(password, Dict, Password) 
            ;   throw(http_exception('Missing password.', 400)) 
            ),
            (   query('SELECT * FROM "user" WHERE email = ?', [Email], User) 
            ;   throw(http_exception('Invalid credentals.', 400))
            ),
            close_conn,
            User = row(Id, _, HashedPassword),
            (   crypto_password_hash(Password, HashedPassword) 
            ;   throw(http_exception('Invalid credentals.', 400))
            ),
            http_set_session_options([ cookie(sess) ]),
            http_session_assert(user_id(Id)),
            reply_json(_{ success: true, message: 'You''ve logged in successfully.' })
        ),
        http_exception(Message, Code),
        (   close_conn
        ,   reply_json(_{ success: false, message: Message }, [ status(Code) ])
        )
    ).



logout(_Request) :-
    (   user_is_logged
    ->  http_session_id(Id),
        http_close_session(Id),
        reply_json(_{ success: true, message: 'You''ve logged out successfully.' })
    ;   reply_json(_{ success: false, message: 'Forbidden.' }, [ status(403) ])
    ).



get_email_validation_error(Email, Sanitized, Error) :-
    normalize_space(atom(Sanitized), Email),
    string_length(Sanitized, Length),
    (   Length == 0
    ->  Error = 'Email address is required.'
    ;   Length < 7
    ->  Error = 'Email address must be at least 7 characters long.'
    ;   Length > 150
    ->  Error = 'Email address must be at most 150 characters long.'
    ;   not(re_match("^[_a-z0-9-]+(\\.[_a-z0-9-]+)*@[a-z0-9-]+(\\.[a-z0-9-]+)*(\\.[a-z]{2,3})$", Sanitized))
    ->  Error = 'Email address is invalid.'
    ;   query('SELECT * FROM "user" WHERE email = ?', [Sanitized], _)
    ->  Error = 'Email is already taken. Login or use another one.'
    ;   Error = null
    ).



get_password_validation_error(Password, RepeatPassword, Error) :-
    string_length(Password, Length),
    (   Length == 0
    ->  Error = 'Password is required.'
    ;   Length < 12
    ->  Error = 'Password must be at least 12 characters long.'
    ;   Length > 50
    ->  Error = 'Password must be at most 50 characters long.'
    ;   not(re_match("^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9])(?=.*[a-z]).{12,50}$", Password))
    ->  Error = 'Password must contain lowercase, uppercase letters, digit and special characters.'
    ;   Password \= RepeatPassword
    ->  Error = 'Both passwords must be identical.'
    ;   Error = null
    ).



registration(Request) :-
    catch(
        (
            init_conn,
            (   not(user_is_logged) 
            ;   throw(http_exception('Forbidden.', 403))
            ),
            (   check_csrf(Request) 
            ;   throw(http_exception('Invalid CSRF token.', 400))
            ),
            (   http_read_json_dict(Request, Dict) 
            ;   throw(http_exception('Invalid content.', 400))
            ),
            (   get_dict(email, Dict, Email) 
            ;   throw(http_exception('Missing email.', 400))
            ),
            (   get_dict(password, Dict, Password) 
            ;   throw(http_exception('Missing password.', 400))
            ),
            (   get_dict(repeat_password, Dict, RepeatPassword) 
            ;   throw(http_exception('Missing repeated password.', 400))
            ),
            (   get_email_validation_error(Email, SanitizedEmail, EmailError) 
            ;   true
            ),
            (   get_password_validation_error(Password, RepeatPassword, PasswordError) 
            ;   true
            ),
            (   ( EmailError \= null ; PasswordError \= null ) 
            ->  reply_json(_{ success: false, errors: _{ email: EmailError, password: PasswordError } }, [ status(400) ])
            ;   (   crypto_password_hash(Password, HashedPassword) 
                ;   throw(http_exception('Internal server error.', 500))
                ),
                (   query('INSERT INTO "user" (email, password) VALUES(?, ?)', [SanitizedEmail, HashedPassword], _) 
                ;   throw(http_exception('Internal server error.', 500))
                ),
                close_conn,
                reply_json(_{ success: true, message: 'You''ve registered successfully. Now you can login.' })
            )
        ),
        http_exception(Message, Code),
        (   close_conn
        ,   reply_json(_{ success: false, message: Message }, [ status(Code) ])
        )
    ).



get_string_validation_error(String, ParamName, MaxChars, Error) :-
    string_length(String, Length),
    (   Length == 0
    ->  format(atom(Error), '~w is required.', ParamName)
    ;   Length > MaxChars
    ->  format(atom(Error), '~w must be at most ~w characters long.', [ParamName, MaxChars])
    ;   Error = null
    ).



and(A, B, Result) :-
    (A, B) 
    ->  Result = true 
    ;   Result = false.



get_additional_parameters_validation_errors([], Errors, HasError) :-
    Errors = [],
    HasError = false.

get_additional_parameters_validation_errors([P|Ps], Errors, HasError) :-
    Error = _{ name: false, value: false },
    (   get_dict(name, P, Name) 
    ->  get_string_validation_error(Name, 'Additional parameter name', 255, NameError)
    ;   NameError = 'Missing additional parameter name.'
    ),
    (   get_dict(value, P, Value) 
    ->  get_string_validation_error(Value, 'Additional parameter value', 255, ValueError)
    ;   ValueError = 'Missing additional parameter value.'
    ),
    b_set_dict(name, Error, NameError),
    b_set_dict(value, Error, ValueError),
    get_additional_parameters_validation_errors(Ps, Es, HasErr),
    Errors = [Error|Es],
    (   ( NameError == null , ValueError == null , HasErr == false )
    ->  HasError = false
    ;   HasError = true
    ).



request_method([], Value) :-
    Value = ''.

request_method([P|Ps], Value) :-
    (   method(Value) = P
    ;   request_method(Ps, Value)
    ).



request_path_info([], Value) :-
    Value = ''.

request_path_info([P|Ps], Value) :-
    (   path_info(Value) = P
    ;   request_path_info(Ps, Value)
    ).



notes_action(Request) :-
    init_conn,
    catch(
        (
            request_method(Request, Method),
            request_path_info(Request, Path),
            % format('Content-Type: text/plain~n~nPath: ~w~nMethod: ~w~nRequest: ~w~n', [Path, Method, Request]),
            (   ( Path == '' ; Path == '/' )
            ->  (   Method == post
                ->  create_note_action(Request)
                ;   Method == get
                ->  get_notes_action(Request)
                ;   throw(http_exception('Method not allowed.', 405))
                )
            ;   re_match("^/[1-9]\\d{0,10}$", Path)
            ,   (   Path \= false
                ;   throw(http_exception('Not found.', 404))
                )
            % Get note id
            ,   split_string(Path, '/', '', Tokens)
            ,   nth1(2, Tokens, NoteIdString)
            ,   atom_number(NoteIdString, NoteId)
            ,   (   Method == get
                ->  get_note_action(NoteId, Request)
                ;   Method == put
                ->  update_note_action(NoteId, Request)
                ;   Method == delete
                ->  delete_note_action(NoteId, Request)
                ;   throw(http_exception('Method not allowed.', 404))
                )
            )
        ),
        http_exception(Error, Code),
        reply_json(_{ success: false, message: Error }, [ status(Code) ])
    ),
    close_conn.
    


get_notes_action(Request) :-
    catch(
        (
            (   logged_user_id(UserId)
            ;   throw(http_exception('Forbidden.', 403))
            ),
            http_clean_location_cache,
            (   get_notes_as_json(UserId, Json)
            ;   throw(http_exception('Internal server error.', 500))
            ),
            reply_json(_{ success: true, data: Json })
        ),
        http_exception(Message, Code),
        reply_json(_{ success: false, message: Message }, [ status(Code) ])
    ).



get_notes_query_and_params(UserId, Query, Params) :-
    get_notes_query_and_params(UserId, null, Query, Params).

get_notes_query_and_params(UserId, NoteId, Query, Params) :-
    Q = 'SELECT JSONB_SET(
            JSON_BUILD_OBJECT(''id'', n.id, ''title'', n.title, ''content'', n.content, ''created_at'', n.created_at)::JSONB, 
            ''{additional_parameters}'', 
            (COALESCE(JSONB_AGG(JSON_BUILD_OBJECT(''id'', ap.id, ''name'', ap.name, ''value'', ap.value)) FILTER (WHERE ap.note_id IS NOT NULL), ''[]''))
        )
        FROM note n 
        LEFT JOIN additional_parameter ap ON ap.note_id = n.id 
        GROUP BY n.id
        HAVING n.user_id = ? ~w
        ORDER BY n.id',
    (   NoteId == null
    ->  (   Completion = '' 
        ,   Params = [UserId]
        )
    ;   (   Completion = ' AND n.id = ?' 
        ,   Params = [UserId, NoteId]
        )
    ),
    format(atom(Query), Q, Completion).



get_notes_as_json(UserId, Json) :-
    get_notes_query_and_params(UserId, Query, Params),
    fetch_all(Query, Params, Result),
    rows_to_json(Result, Json).



get_note_as_json(UserId, NoteId, Json) :-
    get_notes_query_and_params(UserId, NoteId, Query, Params),
    query(Query, Params, Result),
    row_to_json(Result, Json).



rows_to_json([], Result) :-
    Result = [].

rows_to_json([S|Ss], Result) :-
    row_to_json(S, Json),
    rows_to_json(Ss, R),
    Result = [ Json | R ].



row_to_json(Row, Json) :-
    Row = row(Data),
    atom_json_term(Data, Json, [ as(string) ]).



create_note_action(Request) :-
    catch(
        (
            enable_transactions,
            (   logged_user_id(UserId)
            ;   throw(http_exception('Forbidden.', [], 403))
            ),
            validate_save_note_request(Request, Data, Errors, HasErrors),
            (   HasErrors == false
            ;   throw(http_exception('Bad request data.', Errors, 400))
            ),
            (   query('INSERT INTO note (title, content, user_id) VALUES(?, ?, ?) RETURNING *', [Data.title, Data.content, UserId], Note)
            ;   throw(http_exception('Internal server error.', [], 500))
            ),
            Note = row(NoteId, _, _, _, _),
            (   Data.additional_params == []
            ;   get_additional_params_insert_query_and_values(Data.additional_params, NoteId, UserId, Query, QueryParams)
            ,   query(Query, QueryParams, _)
            ;   throw(http_exception('Internal server error.', [], 500))
            ),
            commit,
            get_note_as_json(UserId, NoteId, NoteFromDb),
            reply_json(_{ success: true, data: NoteFromDb })
        ),
        http_exception(Message, Errors, Code),
        (   rollback
        ,   (   Errors == []
            ->  Response = _{ success: false, message: Message }
            ;   Response = _{ success: false, message: Message, errors: Errors }
            )
        ,   reply_json(Response, [ status(Code) ])
        )
    ).



get_additional_params_insert_query_and_values([], NoteId, UserId, Query, QueryParams) :-
    Query = null,
    QueryParams = [].

get_additional_params_insert_query_and_values([AP], NoteId, UserId, Query, QueryParams) :-
    Query = 'INSERT INTO additional_parameter (name, value, note_id, user_id) VALUES (?,?,?,?)',
    QueryParams = [ AP.name | [ AP.value | [ NoteId | [ UserId ] ] ] ].

get_additional_params_insert_query_and_values([AdditionalParam|APs], NoteId, UserId, Query, QueryParams) :-
    get_additional_params_insert_query_and_values(APs, NoteId, UserId, Q, QPs),
    atom_concat(Q, ',(?,?,?,?)', Query),
    QueryParams = [ AdditionalParam.name | [ AdditionalParam.value | [ NoteId | [ UserId | QPs ] ] ] ].



get_note_action(NoteId, Request) :-
    catch(
        (
            (   logged_user_id(UserId)
            ;   throw(http_exception('Forbidden.', 403))
            ),
            (   get_note_as_json(UserId, NoteId, Json)
            ;   throw(http_exception('Not found.', 404))
            ),
            reply_json(_{ success: true, data: Json })
        ),
        http_exception(Message, Code),
        reply_json(_{ success: false, message: Message }, [ status(Code) ])
    ).



validate_save_note_request(Request, Data, Errors, HasErrors) :-
    (   http_read_json_dict(Request, Dict, [ json_object(dict) ])
    ->  (   get_dict(title, Dict, Title)
        ->  get_string_validation_error(Title, 'Title', 255, TitleError)
        ;   TitleError = 'Missing title.'
        ),
        (   get_dict(content, Dict, Content)
        ->  get_string_validation_error(Content, 'Content', 4095, ContentError)
        ;   ContentError = 'Missing content.'
        ),
        (   get_dict(additional_parameters, Dict, AdditionalParams)
        ->  get_additional_parameters_validation_errors(AdditionalParams, AdditionalParamsError, HasAdditionalParamsError)
        ;   AdditionalParamsError = 'Missing additional parameters key.'
        ),
        (   TitleError == null , ContentError == null , HasAdditionalParamsError == false
        ->  Data = _{ title: Title, content: Content, additional_params: AdditionalParams }
        ,   Errors = []
        ,   HasErrors = false
        ;   Data = _{}
        ,   Errors = _{ title: TitleError, content: ContentError, additional_parameters: AdditionalParamsError }
        ,   HasErrors = true
        )
    ;   Data = _{}
    ,   Errors = []
    ,   HasErrors = true
    ).



update_note_action(NoteId, Request) :-
    catch(
        (
            enable_transactions,
            (   logged_user_id(UserId)
            ;   throw(http_exception('Forbidden.', [], 403))
            ),
            (   query('SELECT * FROM note WHERE id = ? AND user_id = ?', [NoteId, UserId], _)
            ;   throw(http_exception('Not found.', 404))
            ),
            validate_save_note_request(Request, Data, Errors, HasErrors),
            (   HasErrors == false
            ;   throw(http_exception('Bad request data.', Errors, 400))
            ),
            (   query('UPDATE note SET title = ?, content = ? WHERE id = ?', [Data.title, Data.content, NoteId], _)
            ,   query('DELETE FROM additional_parameter WHERE note_id = ?', [NoteId], _)
            ,   (   Data.additional_params == []
                ;   get_additional_params_insert_query_and_values(Data.additional_params, NoteId, UserId, Query, QueryParams)
                ,   query(Query, QueryParams, _)
                )
            ;   throw(http_exception('Internal server error.', [], 500))
            ),
            commit,
            get_note_as_json(UserId, NoteId, NoteFromDb),
            reply_json(_{ success: true, data: NoteFromDb })
        ),
        http_exception(Message, Errors, Code),
        (   rollback
        ,   (   Errors == []
            ->  Response = _{ success: false, message: Message }
            ;   Response = _{ success: false, message: Message, errors: Errors }
            )
        ,   reply_json(Response, [ status(Code) ])
        )
    ).



delete_note_action(NoteId, Request) :-
    catch(
        (
            (   logged_user_id(UserId)
            ;   throw(http_exception('Forbidden.', 403))
            ),
            http_clean_location_cache,
            (   query('DELETE FROM note WHERE id = ? AND user_id = ?', [NoteId, UserId], _)
            ;   throw(http_exception('Not found.', 404))
            ),
            reply_json(_{ success: true, message: 'Your note with given ID doesn''t exist anymore.' })
        ),
        http_exception(Message, Code),
        reply_json(_{ success: false, message: Message }, [ status(Code) ])
    ).



print_file_contents(File) :-
    open(File, read, Stream),
    repeat,
    read_line_to_string(Stream, Line),
    (   Line == end_of_file
    ->  true
    ;   write(Line),
        fail
    ),
    close(Stream).
