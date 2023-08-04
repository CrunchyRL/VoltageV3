#include "Console.hpp"

ConsoleComponent::ConsoleComponent() : Component("Console", "Displays and manages the standard out stream.")
{
	OnCreate();
}

ConsoleComponent::~ConsoleComponent()
{
	OnDestroy();
}

void ConsoleComponent::OnCreate()
{
	OutputHandle = nullptr;
	OutputFile = nullptr;
	WriteToLog = true;
	WriteTimestamp = false;
}

void ConsoleComponent::OnDestroy()
{
	LogFile.close();

	if (OutputFile)
	{
		FreeConsole();
	}
}

void ConsoleComponent::Write(const std::string& text, CTextColors textColor)
{
	WriteInternal(text, textColor);
}

void ConsoleComponent::WriteInternal(std::string text, CTextColors textColor)
{
	SetTextColor(textColor);

	if (WriteTimestamp)
	{
		text = GetTimestamp(true) + text;
	}

	std::cout << text << std::endl;

	if (WriteToLog)
	{
		LogFile << text << std::endl;
		LogFile.flush();
	}

	SetTextColor(CTextColors::BrightWhite);
}

void ConsoleComponent::Warning(const std::string& text)
{
	WriteInternal(text, CTextColors::Yellow);
}

void ConsoleComponent::Error(const std::string& text)
{
	WriteInternal(text, CTextColors::Red);
}

void ConsoleComponent::Success(const std::string& text)
{
	WriteInternal(text, CTextColors::LightGreen);
}

void ConsoleComponent::Notify(const std::string& text)
{
	WriteInternal(text, CTextColors::LightBlue);
}

void ConsoleComponent::WriteLog(const std::string& text)
{
	std::string finaltext = text;

	if (WriteTimestamp)
	{
		finaltext = GetTimestamp(true) + text;
	}

	LogFile << finaltext << std::endl;
	LogFile.flush();
}

void ConsoleComponent::Initialize(const std::filesystem::path& directory, const std::string& fileName, const std::string& windowName)
{
	OutputHandle = nullptr;
	OutputFile = nullptr;
	WriteToLog = true;
	WriteTimestamp = true;

	// Open the standard out stream and show the window, then grab its handle so we can set the text color.
	
	if (Events.showconsoleterminalwindow)
	{
		AllocConsole();
		freopen_s(&OutputFile, "CONOUT$", "w", stdout);
		ShowWindow(GetConsoleWindow(), SW_SHOW);
		SetConsoleTitle(std::wstring(windowName.begin(), windowName.end()).c_str());
		OutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	}

	if (WriteToLog)
	{
		std::string filename = fileName + "-" + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) + ".log";
		LogFile.open(directory / filename);
	}

	Write(GetNameFormatted() + "Initialized!");
}

void ConsoleComponent::ToggleLogging(bool bWriteToLog)
{
	WriteToLog = bWriteToLog;
}

void ConsoleComponent::ToggleTimestamp(bool bWriteTimestamp)
{
	WriteTimestamp = bWriteTimestamp;
}

void ConsoleComponent::SetTextColor(CTextColors textColor)
{
	if (OutputHandle)
	{
		SetConsoleTextAttribute(OutputHandle, static_cast<uint16_t>(textColor));
	}
}

std::string ConsoleComponent::GetTimestamp(const bool& bWithSpace)
{
	std::tm local;
	std::time_t time = std::time(nullptr);
	localtime_s(&local, &time);

	std::ostringstream timeStream;
	timeStream << "[";
	timeStream << std::setfill('0') << std::setw(2) << std::right << std::to_string(local.tm_hour);
	timeStream << ":";
	timeStream << std::setfill('0') << std::setw(2) << std::right << std::to_string(local.tm_min);
	timeStream << ":";
	timeStream << std::setfill('0') << std::setw(2) << std::right << std::to_string(local.tm_sec);
	timeStream << "]" << (bWithSpace ? " " : "");

	return timeStream.str();
}

class ConsoleComponent Console{};