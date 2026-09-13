package dev.camada;

/**
 * What {@link Camada#handle} returns: an {@link Answer} means camada fully answered the request
 * (block, challenge, verify, beacon endpoints); a {@link Passed} means run the app, stamp the rid
 * header and session cookie on its response, and call onFinish(status) once when it is done.
 */
public sealed interface Result permits Answer, Passed {}
