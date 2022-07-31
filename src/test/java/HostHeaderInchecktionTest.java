import java.lang.reflect.Method;

public class HostHeaderInchecktionTest {

    public static void main(String[] args) {
        try {
            Method main = Class.forName("burp.StartBurp").getMethod("main", String[].class);
            main.invoke(null, (Object) args);
        } catch (Exception e) {
            throw new RuntimeException("Could not start burp.", e);
        }
    }
}
