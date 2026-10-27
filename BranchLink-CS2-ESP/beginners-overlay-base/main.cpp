#include "overlay.h"
#include "MemoryManager.hpp"


// Global variables
uintptr_t GetPlayer(uint32_t i) {
	uintptr_t entityList = mem.Read<uintptr_t>(module_base + 0x271A908); // dwEntityList, offsets.hpp (list of all players in game)


	uintptr_t listEntry = mem.Read<uintptr_t>(entityList + (8 * ((i & 0x7FFF) >> 9)) + 16); // m_hPlayerPawn, cliend_dll.hpp (list of all players in game)
	if (!listEntry) return 0;

	uintptr_t controller = mem.Read<uintptr_t>(listEntry + 112 * (i & 0x1FF)); // m_hPlayerController, cliend_dll.hpp (controller handle, ссылка на контроллер игрока)

	if (controller < 0x1000000 || (controller >> 48) != 0) return 0;

	// m_hPlayerPawn
	uint32_t pawnHandle = mem.Read<uint32_t>(controller + 0x92C); // m_hPlayerPawn, cliend_dll.hpp (pawn handle, ссылка на игровую сущность игрока)
	if (!pawnHandle) return 0;


	uintptr_t listEntry2 = mem.Read<uintptr_t>(entityList + (8 * ((pawnHandle & 0x7FFF) >> 9)) + 16);
	if (!listEntry2) return 0;


	uintptr_t pawn = mem.Read<uintptr_t>(listEntry2 + 112 * (pawnHandle & 0x1FF));

	return pawn;
}


// Get the 3D location of the player pawn by the type Vector3 (x - left/right, y - forward/backward, z - up/down) (vector2 = x, y)
Vector3 GetLocationOfPlayer(uintptr_t player) {
	return mem.Read<Vector3>(player + 0x14A4); // m_vOldOrigin, client_dll.hpp (m_vOldOrigin = my position)
}


// true — точка перед камерой, screen заполнен; false — точка за спиной
bool WorldToScreen(Vector3 pos, Vector2& screen)
{
	Matrix4x4 matrix = mem.Read<Matrix4x4>(module_base + 0x256B020); // dwViewMatrix

	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);

	float w = matrix.m[3][0] * pos.x + matrix.m[3][1] * pos.y + matrix.m[3][2] * pos.z + matrix.m[3][3];
	if (w < 0.01f)
		return false;

	float invW = 1.0f / w;
	float x = (matrix.m[0][0] * pos.x + matrix.m[0][1] * pos.y + matrix.m[0][2] * pos.z + matrix.m[0][3]) * invW;
	float y = (matrix.m[1][0] * pos.x + matrix.m[1][1] * pos.y + matrix.m[1][2] * pos.z + matrix.m[1][3]) * invW;

	screen.x = (screenWidth / 2.0f) * (1.0f + x);
	screen.y = (screenHeight / 2.0f) * (1.0f - y);
	return true;
}


// Направление на врага вокруг точки center (вид сверху, 360)
Vector2 RadarDirection(Vector3 me, Vector3 enemy, float yawDeg, Vector2 center, float radius)
{
	float dx = enemy.x - me.x;
	float dy = enemy.y - me.y;

	const float DEG2RAD = 3.14159265f / 180.0f;
	float a = atan2f(dy, dx) - yawDeg * DEG2RAD; // угол относительно взгляда

	// a = 0 (вверх), a = +90° (влево, a = 180 (вниз), a = -90° (вправо)
	Vector2 dir(-sinf(a), -cosf(a));

	return center + dir * radius;
}

// Текст, отцентрованный по X относительно pos, с тенью для читаемости
void DrawTextCentered(Vector2 pos, const char* text, ImU32 color)
{
	ImVec2 size = ImGui::CalcTextSize(text);
	Vector2 topLeft(pos.x - size.x / 2.0f, pos.y);

	DrawString(topLeft + Vector2(1, 1), text, Colors::Black); // тень
	DrawString(topLeft, text, color);
}

// Плавный цвет: красный (близко) → жёлтый → зелёный (далеко)
ImU32 DistanceColor(float meters)
{
	const float nearM = 5.0f;   // ближе — полностью красный
	const float farM = 50.0f;  // дальше — полностью зелёный

	float t = (meters - nearM) / (farM - nearM);
	t = fmaxf(0.0f, fminf(t, 1.0f));               // clamp в 0..1

	int r, g;
	if (t < 0.5f)
	{
		r = 255;                                    // красный на максимуме
		g = (int)(255 * (t * 2.0f));               // зелёный растёт 0 → 255
	}
	else
	{
		r = (int)(255 * ((1.0f - t) * 2.0f));      // красный падает 255 → 0
		g = 255;                                    // зелёный на максимуме
	}
	return Color(r, g, 0);
}


// Main drawing function, called every frame by the overlay
void MyDrawings()
{
	// Get the My local Player pawn
	uintptr_t localPawn = mem.Read<uintptr_t>(module_base + 0x2565718);   // dwLocalPlayerPawn
	if (!localPawn) return;

	Vector3 me = GetLocationOfPlayer(localPawn);
	float   yaw = mem.Read<float>(module_base + 0x257BCC8 + 4);          // dwViewAngles.y

	Vector2 center(960, 950); // center of the radar (screen coordinates)

	// 64 is the maximum number of players in a CS2 match, i = counter
	for (size_t i = 0; i < 64; i++)
	{
		auto player = GetPlayer(i);
		if (!player || player == localPawn) continue;

		Vector3 enemy = GetLocationOfPlayer(player);

		// Число → текст: "%.0f" = float без знаков после запятой
		float distMeters = me.Distance(enemy) * 0.0254f;
		ImU32 col = DistanceColor(distMeters);

		char text[32];
		snprintf(text, sizeof(text), "%.0f m", distMeters);

		Vector2 feet;
		if (WorldToScreen(enemy, feet))
		{
			DrawLine(center, feet, col, 2.0f);
			DrawTextCentered(feet + Vector2(0, 4), text, col);
		}
		else
		{
			Vector2 end = RadarDirection(me, enemy, yaw, center, 150.0f);
			DrawLine(center, end, col, 2.0f);
			DrawTextCentered(end, text, col);
		}

	}
}

// CTRL + K + CTRL + D = auto-format code in Visual Studio

int main()
{

	// 1. Attach to your memory-target process name (e.g. cs2)
	if (!mem.Attach(L"cs2.exe")) {
		std::wcerr << L"Failed to find or open process!" << std::endl;
		return 1;
	}
	std::wcout << L"Successfully attached!" << std::endl;

	// 2. Find the module base address
	module_base = mem.GetModuleBaseAddress(L"client.dll");
	std::cout << "Module Base Address: 0x" << std::hex << module_base << std::endl;

	RunOverlay(MyDrawings);
	return 0;
}