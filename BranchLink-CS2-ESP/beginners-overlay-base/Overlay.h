#pragma once
// =====================================================================
//  overlay.h  -  A simple transparent ImGui overlay for beginners
// ---------------------------------------------------------------------
//  HOW TO USE:
//
//      #include "overlay.h"
//
//      void MyDrawings()
//      {
//          DrawLine(Vector2(0, 0), Vector2(500, 500), Colors::Red);
//          DrawBox(Vector2(100, 100), 50, 100, Colors::Green);
//      }
//
//      int main()
//      {
//          RunOverlay(MyDrawings);   // <- that's it!
//      }
//
//  HOTKEYS:
//      INSERT = show / hide the menu
//      END    = close the overlay
// =====================================================================

#include <Windows.h>
#include <dwmapi.h>
#include <d3d11.h>
#include <cmath>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "d3dcompiler.lib")

// ImGui needs this to receive mouse and keyboard input from our window
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// =====================================================================
//  Vector2  -  a point on your SCREEN (x, y)
// =====================================================================
struct Vector2
{
    float x = 0.0f;
    float y = 0.0f;

    Vector2() = default;
    Vector2(float x, float y) : x(x), y(y) {}

    Vector2 operator+(const Vector2& other) const { return Vector2(x + other.x, y + other.y); }
    Vector2 operator-(const Vector2& other) const { return Vector2(x - other.x, y - other.y); }
    Vector2 operator*(float scale)          const { return Vector2(x * scale, y * scale); }
    Vector2 operator/(float scale)          const { return Vector2(x / scale, y / scale); }

    // How long this vector is
    float Length() const { return sqrtf(x * x + y * y); }

    // How far away another point is
    float Distance(const Vector2& other) const { return (*this - other).Length(); }
};

// =====================================================================
//  Vector3  -  a position in the 3D GAME WORLD (x, y, z)
// =====================================================================
struct Vector3
{
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;

    Vector3() = default;
    Vector3(float x, float y, float z) : x(x), y(y), z(z) {}

    Vector3 operator+(const Vector3& other) const { return Vector3(x + other.x, y + other.y, z + other.z); }
    Vector3 operator-(const Vector3& other) const { return Vector3(x - other.x, y - other.y, z - other.z); }
    Vector3 operator*(float scale)          const { return Vector3(x * scale, y * scale, z * scale); }
    Vector3 operator/(float scale)          const { return Vector3(x / scale, y / scale, z / scale); }

    float Length() const { return sqrtf(x * x + y * y + z * z); }
    float Distance(const Vector3& other) const { return (*this - other).Length(); }
};

struct Matrix4x4
{
    float m[4][4];
};


// =====================================================================
//  Colors
// =====================================================================

// Make your own color: Color(red, green, blue, alpha)  - each from 0 to 255
inline ImU32 Color(int r, int g, int b, int a = 255)
{
    return IM_COL32(r, g, b, a);
}

namespace Colors
{
    const ImU32 White = IM_COL32(255, 255, 255, 255);
    const ImU32 Black = IM_COL32(0, 0, 0, 255);
    const ImU32 Red = IM_COL32(255, 0, 0, 255);
    const ImU32 Green = IM_COL32(0, 255, 0, 255);
    const ImU32 Blue = IM_COL32(0, 120, 255, 255);
    const ImU32 Yellow = IM_COL32(255, 255, 0, 255);
    const ImU32 Orange = IM_COL32(255, 165, 0, 255);
    const ImU32 Purple = IM_COL32(170, 0, 255, 255);
}

// =====================================================================
//  Drawing functions  -  call these inside YOUR drawing function
// =====================================================================

// Draws a line from one point to another
inline void DrawLine(Vector2 from, Vector2 to, ImU32 color = Colors::White, float thickness = 1.0f)
{
    ImGui::GetBackgroundDrawList()->AddLine(ImVec2(from.x, from.y), ImVec2(to.x, to.y), color, thickness);
}

// Draws an empty box. 'topLeft' is the top-left corner of the box.
inline void DrawBox(Vector2 topLeft, float width, float height, ImU32 color = Colors::White, float thickness = 1.0f)
{
    ImGui::GetBackgroundDrawList()->AddRect(
        ImVec2(topLeft.x, topLeft.y),
        ImVec2(topLeft.x + width, topLeft.y + height),
        color, 0.0f, 0, thickness);
}

// Draws a box filled with color (tip: use a low alpha like Color(0,0,0,100) for see-through)
inline void DrawFilledBox(Vector2 topLeft, float width, float height, ImU32 color = Colors::White)
{
    ImGui::GetBackgroundDrawList()->AddRectFilled(
        ImVec2(topLeft.x, topLeft.y),
        ImVec2(topLeft.x + width, topLeft.y + height),
        color);
}

// Draws an empty circle
inline void DrawCircle(Vector2 center, float radius, ImU32 color = Colors::White, float thickness = 1.0f)
{
    ImGui::GetBackgroundDrawList()->AddCircle(ImVec2(center.x, center.y), radius, color, 0, thickness);
}

// Draws text on the screen
// (named DrawString because Windows already uses the name "DrawText")
inline void DrawString(Vector2 position, const char* text, ImU32 color = Colors::White)
{
    ImGui::GetBackgroundDrawList()->AddText(ImVec2(position.x, position.y), color, text);
}

// Returns the size of your screen, e.g. (1920, 1080)
inline Vector2 GetScreenSize()
{
    return Vector2((float)GetSystemMetrics(SM_CXSCREEN), (float)GetSystemMetrics(SM_CYSCREEN));
}

// =====================================================================
//  Internal stuff  -  you don't need to touch anything below this line
// =====================================================================
namespace OverlayInternal
{
    static HWND                    window = nullptr;
    static ID3D11Device* device = nullptr;
    static ID3D11DeviceContext* context = nullptr;
    static IDXGISwapChain* swapChain = nullptr;
    static ID3D11RenderTargetView* renderTarget = nullptr;

    inline LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        switch (msg)
        {
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) // disable the ALT menu
                return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    inline bool CreateOverlayWindow()
    {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_CLASSDC;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"SimpleOverlayClass";
        RegisterClassExW(&wc);

        Vector2 screen = GetScreenSize();

        // TOPMOST     = always on top of other windows
        // LAYERED     = allows transparency
        // TRANSPARENT = mouse clicks go through the window
        // TOOLWINDOW  = hides it from the taskbar
        window = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
            wc.lpszClassName, L"Simple Overlay", WS_POPUP,
            0, 0, (int)screen.x, (int)screen.y,
            nullptr, nullptr, wc.hInstance, nullptr);

        if (!window)
            return false;

        SetLayeredWindowAttributes(window, RGB(0, 0, 0), 255, LWA_ALPHA);

        // Makes the black background fully see-through
        MARGINS margins = { -1 };
        DwmExtendFrameIntoClientArea(window, &margins);

        ShowWindow(window, SW_SHOWDEFAULT);
        UpdateWindow(window);
        return true;
    }

    inline bool CreateDirectX()
    {
        DXGI_SWAP_CHAIN_DESC sd = {};
        sd.BufferCount = 2;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = window;
        sd.SampleDesc.Count = 1;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

        D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
        D3D_FEATURE_LEVEL featureLevel;

        HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            levels, 2, D3D11_SDK_VERSION, &sd, &swapChain, &device, &featureLevel, &context);

        // If the graphics card doesn't support it, fall back to software rendering
        if (hr == DXGI_ERROR_UNSUPPORTED)
            hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0,
                levels, 2, D3D11_SDK_VERSION, &sd, &swapChain, &device, &featureLevel, &context);

        if (FAILED(hr))
            return false;

        ID3D11Texture2D* backBuffer = nullptr;
        swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
        device->CreateRenderTargetView(backBuffer, nullptr, &renderTarget);
        backBuffer->Release();
        return true;
    }

    inline void Cleanup()
    {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        if (renderTarget) { renderTarget->Release(); renderTarget = nullptr; }
        if (swapChain) { swapChain->Release();    swapChain = nullptr; }
        if (context) { context->Release();      context = nullptr; }
        if (device) { device->Release();       device = nullptr; }

        DestroyWindow(window);
        UnregisterClassW(L"SimpleOverlayClass", GetModuleHandleW(nullptr));
    }

    // Click-through ON  = clicks go to the game
    // Click-through OFF = clicks go to our menu
    inline void SetClickThrough(bool enabled)
    {
        LONG_PTR style = GetWindowLongPtrW(window, GWL_EXSTYLE);
        if (enabled) style |= WS_EX_TRANSPARENT;
        else         style &= ~WS_EX_TRANSPARENT;
        SetWindowLongPtrW(window, GWL_EXSTYLE, style);
    }

    // Returns true only once each time the key is pressed
    inline bool KeyPressed(int key, bool& wasDown)
    {
        bool isDown = (GetAsyncKeyState(key) & 0x8000) != 0;
        bool pressed = isDown && !wasDown;
        wasDown = isDown;
        return pressed;
    }
}

// =====================================================================
//  RunOverlay  -  the ONE function you call from main()
// =====================================================================
inline void RunOverlay(void (*drawFunction)())
{
    using namespace OverlayInternal;

    SetProcessDPIAware(); // so screen coordinates are real pixels

    if (!CreateOverlayWindow()) { MessageBoxA(nullptr, "Failed to create overlay window", "Error", MB_OK); return; }
    if (!CreateDirectX()) { MessageBoxA(nullptr, "Failed to create DirectX", "Error", MB_OK); return; }

    // Set up ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr; // don't create an imgui.ini file
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(device, context);

    // Menu options
    bool showMenu = false;
    bool enableDrawings = true;

    bool running = true;
    bool insertWasDown = false;
    bool endWasDown = false;
    HWND previousWindow = nullptr;

    while (running)
    {
        // 1. Handle Windows messages
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                running = false;
        }
        if (!running)
            break;

        // 2. Hotkeys
        if (KeyPressed(VK_END, endWasDown))
            break;

        if (KeyPressed(VK_INSERT, insertWasDown))
        {
            showMenu = !showMenu;
            SetClickThrough(!showMenu);

            if (showMenu)
            {
                previousWindow = GetForegroundWindow(); // remember the game window
                SetForegroundWindow(window);            // so the menu can receive clicks
            }
            else if (previousWindow)
            {
                SetForegroundWindow(previousWindow);    // give focus back to the game
            }
        }

        // 3. Start a new frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // 4. The menu
        if (showMenu)
        {
            ImGui::Begin("Overlay Menu", nullptr, ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::Text("INSERT = show/hide menu   END = exit");
            ImGui::Separator();
            ImGui::Checkbox("Enable drawings", &enableDrawings);
            if (ImGui::Button("Exit"))
                running = false;
            ImGui::End();
        }

        // 5. Your drawings
        if (enableDrawings && drawFunction)
            drawFunction();

        // 6. Render everything to the screen
        ImGui::Render();
        const float clearColor[4] = { 0.0f, 0.0f, 0.0f, 0.0f }; // fully transparent
        context->OMSetRenderTargets(1, &renderTarget, nullptr);
        context->ClearRenderTargetView(renderTarget, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        swapChain->Present(1, 0); // 1 = vsync, keeps CPU usage low
    }

    Cleanup();
}