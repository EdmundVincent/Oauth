// 在 run 方法里，userRepository.save(admin) 后面加上：

// --- 初始化一个第三方应用 ---
if (clientRepository.findByClientId("client-app").isEmpty()) {
    Client app = new Client();
    app.setClientId("client-app");
    app.setClientSecret("123456"); // 实际生产中要加密存储
    app.setRedirectUri("http://localhost:8080/callback"); // 假设这是第三方应用的回调
    app.setAppName("Jarvis Demo App");
    clientRepository.save(app);
    System.out.println("初始化测试应用: client_id=client-app, secret=123456");
}