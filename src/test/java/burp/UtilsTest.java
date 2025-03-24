package burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class UtilsTest {


    @Test
    void removeHeader() {
        // arrange
        String httpResponse = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html\r\n"
                            + "Content-Length: 13\r\n"
                            + "\r\n"
                            + "<h1>Hello</h1>";

        // act
        String body = Utils.removeHeader(httpResponse);

        // assert
        assertEquals("<h1>Hello</h1>", body);
    }

    @Test
    void removeHeader_NoBody() {
        // arrange
        String httpResponse = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html\r\n"
                            + "Content-Length: 13\r\n"
                            + "\r\n";

        // act
        String body = Utils.removeHeader(httpResponse);

        // assert
        assertEquals("", body);
    }

    @Test
    void removeHeader_MultipleNewLinesInBody() {
        // arrange
        String httpResponse = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html\r\n"
                            + "Content-Length: 13\r\n"
                            + "\r\n"
                            + "<h1>Hello</h1>\r\n\r\n"
                            + "<p>World</p>";

        // act
        String body = Utils.removeHeader(httpResponse);

        // assert
        assertEquals("<h1>Hello</h1>\r\n\r\n<p>World</p>", body);
    }

}
