import java.net.*;
import java.io.*;
import java.util.*;

class Req {
    public static void main(String[] args) {
        try {
            URL url = new URL("http://192.168.185.245:8000");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");

            Map<String, String> parameters = new HashMap<>();
            parameters.put("param1", "val");

            con.setDoOutput(true);
            DataOutputStream out = new DataOutputStream(con.getOutputStream());
            out.writeBytes(ParameterStringBuilder.getParamsString(parameters));
            out.flush();
            out.close();

            con.setRequestProperty("Content-Type", "application/json");
            String contentType = con.getHeaderField("Content-Type");
            con.setConnectTimeout(5000);
            con.setReadTimeout(5000);

            con.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}