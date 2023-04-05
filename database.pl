:- module(database, [
    query/2, 
    query/3, 
    init_conn/0, 
    init_conn/1, 
    init_conn/2, 
    enable_transactions/0, 
    end_transaction/1, 
    commit/0, 
    rollback/0, 
    close_conn/0, 
    fetch_all/3, 
    get_connection/1,
    fetch/2,
    fetch_all/2,
    fetch_all/3
]).

:- use_module(library(odbc)).
:- use_module(library(crypto)).

:- set_prolog_flag(report_error, true).

odbc_dsn('Note Manager DSN').

% global conn



init_conn :-
    init_conn(_).

init_conn(Connection) :-
    init_conn(Connection, false).

init_conn(Connection, Transaction) :-
    odbc_dsn(DSN),
    odbc_connect(DSN, Connection, []),
    (   Transaction \= true
    ;   odbc_set_connection(Connection, auto_commit(false))
    ),
    nb_setval(conn, Connection).



enable_transactions :-
    (   nb_getval(conn, Connection)
    ;   init_conn(Connection, true)
    ),
    odbc_set_connection(Connection, auto_commit(false)),
    nb_setval(conn, Connection).



end_transaction(Action) :-
    (   Action == commit
    ;   Action == rollback
    ),
    (   nb_getval(conn, Connection)
    ->  odbc_end_transaction(Connection, Action)
    ;   true
    ).


commit :-
    end_transaction(commit).


rollback :-
    end_transaction(rollback).


get_connection(Connection) :-
    catch(
        nb_getval(conn, Connection),
        error(_, _),
        (   init_conn
        ,   nb_getval(conn, Connection)
        )
    ).


close_conn :-
    catch(
        (
            nb_getval(conn, Conn),
            close_conn(Conn),
            nb_delete(conn)
        ),
        error(_, _Ctx),
        true
    ).

close_conn(Connection) :-
    odbc_disconnect(Connection).



query(Query, Result) :-
    query(Query, [], Result).

query(Query, Params, Result) :-
    get_connection(Connection),
    length(Params, N),
    findall(default, between(1, N, _), Placeholders),
    odbc_prepare(Connection, Query, Placeholders, Statement),
    odbc_execute(Statement, Params, Result).



fetch(Statement, Result) :-
    odbc_fetch(Statement, Row, next),
    (   Row == end_of_file
    ->  Result = []
    ;   fetch(Statement, Rows)
    ,   Result = [Row | Rows]
    ).

fetch_all(Query, Result) :-
    fetch_all(Query, [], Result).

fetch_all(Query, Params, Result) :-
    get_connection(Connection),
    length(Params, N),
    findall(default, between(1, N, _), Placeholders),
    odbc_prepare(Connection, Query, Placeholders, Statement, [ fetch(fetch) ]),
    odbc_execute(Statement, Params, _),
    fetch(Statement, Result).
