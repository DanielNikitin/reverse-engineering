// Sk Quirix: https://offsets.getmorphine.fun/offsets.hpp

// Подключение библиотек
#include <Windows.h> // базовые функции Windows (окна, сообщения, поиск окон).
#include <d3d11.h> // DirectX 11
#include <dxgi.h> // DirectX Graphics Infrastructure для работы с графикой.
#include <iostream> // вывод в консоль
#include <string> // работа со строками впаре с iostream

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h" // библиотеки интерфейса + бэкенды под Win32 и DirectX 11

#pragma comment(lib, "d3d11.lib") // говорит компилятору подключить библиотеки DirectX
#pragma comment(lib, "dxgi.lib") // говорит компилятору подключить библиотеки DirectX


// Обработчик сообщений окна
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// WndProc функция, которая получает сообщения от Windows (движение мыши, клики и т.д.) и передаёт их в ImGui
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int main() {
    std::cout << "Searching for Discord Overlay window (waiting up to 60 seconds)...\n";
    std::cout << "Make sure:\n";
    std::cout << "1. Discord is running\n";
    std::cout << "2. Overlay is enabled in Discord settings\n";
    std::cout << "3. Rust is running\n";
    std::cout << "4. Try pressing Shift + ` in the game\n\n";

    // Поиск окна Discord Overlay
    HWND hWnd = nullptr;
    for (int i = 0; i < 600; i++) {          // 600 * 100ms = 60 секунд
        hWnd = FindWindowA("Chrome_WidgetWin_1", "Discord Overlay"); // FindWindowA ищет окно по классу (Chrome_WidgetWin_1) и заголовку (Discord Overlay)
        // Если нашёл - сохраняет его дескриптор в hWnd
        if (hWnd) {
            std::cout << "Found Discord Overlay window!\n";
            break;
        }

        if (i % 10 == 0) {  // каждые 1 секунду пишем статус
            std::cout << "Waiting... " << (i / 10) << "s\n";
        }
        Sleep(100);
    }


    if (!hWnd) {
        std::cout << "\nDiscord Overlay window not found after 60 seconds.\n";
        std::cout << "Try:\n";
        std::cout << "- Restart Discord\n";
        std::cout << "- In Discord: Settings -> Overlay -> Enable Overlay\n";
        std::cout << "- In game press Shift + `\n";
        system("pause");
        return 1;
    }

    // Получаем размер окна
    RECT rect;
    GetClientRect(hWnd, &rect); // возвращает размеры клиентской области окна (без рамок)
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    if (width == 0 || height == 0) {
        width = GetSystemMetrics(SM_CXSCREEN);
        height = GetSystemMetrics(SM_CYSCREEN);
    }

    // Создаём DirectX
    // берём ширину и высоту, чтобы создать SwapChain нужного размера
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = width;
    sd.BufferDesc.Height = height;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd; // привязываем рендер к окну Discord Overlay
	sd.SampleDesc.Count = 1; // без мультисэмплинга
	sd.Windowed = TRUE; // окно в оконном режиме
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD; // стандартный режим обмена буферов

	ID3D11Device* device = nullptr; // устройство DirectX 11
	ID3D11DeviceContext* context = nullptr; // контекст устройства DirectX 11
	IDXGISwapChain* swapChain = nullptr; // Цепочка буфера которая будет рисовать прямо в найденное окно Discord Overlay
	ID3D11RenderTargetView* rtv = nullptr; // рендер-таргет в который будем рисовать

    D3D_FEATURE_LEVEL featureLevel;
    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION, &sd, &swapChain, &device, &featureLevel, &context))) {
        std::cout << "Failed to create D3D11 device\n";
        return 1;
    }

    // Создание Render Target View
    ID3D11Texture2D* backBuffer = nullptr;
    swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    device->CreateRenderTargetView(backBuffer, nullptr, &rtv);
    backBuffer->Release();

    // ImGui
    ImGui::CreateContext();
    ImGui_ImplWin32_Init(hWnd);
    ImGui_ImplDX11_Init(device, context);

    std::cout << "Overlay started. Press END to exit.\n";

    MSG msg = {};

    // Главный цикл
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        if (GetAsyncKeyState(VK_END) & 1)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // ====== КОТИК ======
        ImGui::Begin("Cat Overlay");
        ImGui::Text("Discord Overlay + ImGui");
        ImGui::Separator();

        ImDrawList* draw = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetCursorScreenPos();

        // Мордочка
        draw->AddCircleFilled(ImVec2(p.x + 60, p.y + 60), 50, IM_COL32(255, 180, 100, 255));
        // Ушки
        draw->AddTriangleFilled(ImVec2(p.x + 25, p.y + 35), ImVec2(p.x + 45, p.y + 5), ImVec2(p.x + 65, p.y + 40), IM_COL32(255, 180, 100, 255));
        draw->AddTriangleFilled(ImVec2(p.x + 95, p.y + 35), ImVec2(p.x + 75, p.y + 5), ImVec2(p.x + 55, p.y + 40), IM_COL32(255, 180, 100, 255));
        // Глаза
        draw->AddCircleFilled(ImVec2(p.x + 45, p.y + 55), 7, IM_COL32(30, 30, 30, 255));
        draw->AddCircleFilled(ImVec2(p.x + 75, p.y + 55), 7, IM_COL32(30, 30, 30, 255));
        // Нос
        draw->AddTriangleFilled(ImVec2(p.x + 60, p.y + 68), ImVec2(p.x + 55, p.y + 75), ImVec2(p.x + 65, p.y + 75), IM_COL32(255, 100, 120, 255));

        ImGui::Dummy(ImVec2(120, 130));
        ImGui::Spacing();
        if (ImGui::Button("Meow")) {}
        ImGui::End();
        // ===================

        ImGui::Render();

        float clear[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        context->OMSetRenderTargets(1, &rtv, nullptr);
        context->ClearRenderTargetView(rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        swapChain->Present(1, 0);

        Sleep(1);
    }

    // Очистка ресурсов
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    if (rtv) rtv->Release();
    if (swapChain) swapChain->Release();
    if (context) context->Release();
    if (device) device->Release();

    return 0;
}