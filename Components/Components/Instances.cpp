#include "Instances.hpp"
#include "../Includes.hpp"

InstancesComponent::InstancesComponent() : Component("Instances", "Manages class instances and objects.")
{
	OnCreate();
}

InstancesComponent::~InstancesComponent()
{
	OnDestroy();
}

void InstancesComponent::OnCreate()
{
	I_UCanvas = nullptr;
	I_AHUD = nullptr;
	I_UGameViewportClient = nullptr;
	I_APlayerController = nullptr;
}

void InstancesComponent::OnDestroy()
{
	for (UObject* instance : CreatedInstances)
	{
		if (instance)
		{
			MarkForDestory(instance);
		}
	}
}

class UClass* InstancesComponent::FindStaticClass(const std::string& className)
{
	if (StaticClasses.empty())
	{
		MapObjects();
	}

	if (StaticClasses.find(className) != StaticClasses.end())
	{
		return StaticClasses[className];
	}

	return nullptr;
}

class UFunction* InstancesComponent::FindStaticFunction(const std::string& className)
{
	if (StaticFunctions.empty())
	{
		MapObjects();
	}

	if (StaticFunctions.find(className) != StaticFunctions.end())
	{
		return StaticFunctions[className];
	}

	return nullptr;
}

enum EObjectFlags
{
	RF_NoFlags = 0x00000000,
	RF_Public = 0x00000001,
	RF_Standalone = 0x00000002,
	RF_MarkAsNative = 0x00000004,
	RF_Transactional = 0x00000008,
	RF_ClassDefaultObject = 0x00000010,
	RF_ArchetypeObject = 0x00000020,
	RF_Transient = 0x00000040,
	RF_MarkAsRootSet = 0x00000080,
	RF_TagGarbageTemp = 0x00000100,
	RF_NeedInitialization = 0x00000200,
	RF_NeedLoad = 0x00000400,
	RF_KeepForCooker = 0x00000800,
	RF_NeedPostLoad = 0x00001000,
	RF_NeedPostLoadSubobjects = 0x00002000,
	RF_NewerVersionExists = 0x00004000,
	RF_BeginDestroyed = 0x00008000,
	RF_FinishDestroyed = 0x00010000,
	RF_BeingRegenerated = 0x00020000,
	RF_DefaultSubObject = 0x00040000,
	RF_WasLoaded = 0x00080000,
	RF_TextExportTransient = 0x00100000,
	RF_LoadCompleted = 0x00200000,
	RF_InheritableComponentTemplate = 0x00400000,
	RF_DuplicateTransient = 0x00800000,
	RF_StrongRefOnFrame = 0x01000000,
	RF_NonPIEDuplicateTransient = 0x02000000,
	RF_Dynamic = 0x04000000,
	RF_WillBeLoaded = 0x08000000,
};

void InstancesComponent::MarkInvincible(class UObject* object)
{
	if (object)
	{
		object->ObjectFlags &= ~EObjectFlags::RF_Transient;
		object->ObjectFlags |= EObjectFlags::RF_Public;
		object->ObjectFlags |= EObjectFlags::RF_Standalone;
		object->ObjectFlags |= EObjectFlags::RF_MarkAsRootSet;
	}
}

void InstancesComponent::MarkForDestory(class UObject* object)
{
	if (object)
	{
		object->ObjectFlags = 0;
		object->ObjectFlags = EObjectFlags::RF_Transient;
		object->MarkPendingKill();
	}
}

class UEngine* InstancesComponent::IUEngine()
{
	return I_UEngine;
}

class UAudioDevice* InstancesComponent::IUAudioDevice()
{
	UEngine* engine = IUEngine();

	if (engine)
	{
		UAudioDevice* audioDevice = engine->GetAudioDevice();

		if (audioDevice)
		{
			return audioDevice;
		}
	}

	return nullptr;
}

class AWorldInfo* InstancesComponent::IAWorldInfo()
{
	UEngine* engine = IUEngine();

	if (engine)
	{
		AWorldInfo* worldInfo = engine->GetCurrentWorldInfo();

		if (worldInfo)
		{
			return worldInfo;
		}
	}

	return nullptr;
}

class UCanvas* InstancesComponent::IUCanvas()
{
	return I_UCanvas;
}

class AHUD* InstancesComponent::IAHUD()
{
	return I_AHUD;
}

class UFileSystem* InstancesComponent::IUFileSystem()
{
	return (UFileSystem*)UFileSystem::StaticClass();
}

class UGameViewportClient* InstancesComponent::IUGameViewportClient()
{
	return I_UGameViewportClient;
}

class ULocalPlayer* InstancesComponent::IULocalPlayer()
{
	UEngine* engine = IUEngine();

	if (engine && engine->GamePlayers[0])
	{
		return engine->GamePlayers[0];
	}

	return nullptr;
}

class USaveData_TA* InstancesComponent::IUSaveData_TA()
{
	return Instances.GetInstanceOf<USaveData_TA>();
}

std::string InstancesComponent::GetPlayerName()
{
	ULocalPlayer* localPlayer = IULocalPlayer();

	if (localPlayer)
	{
		return localPlayer->eventGetNickname().ToString();
	}

	return "null";
}

struct FUniqueNetId InstancesComponent::GetUniqueID()
{
	ULocalPlayer* localPlayer = IULocalPlayer();
	
	if (localPlayer)
	{
		return localPlayer->eventGetUniqueNetId();
	}

	return FUniqueNetId{};
}

class APlayerController* InstancesComponent::IAPlayerController()
{
	return I_APlayerController;
}

void InstancesComponent::SetEngine(class UEngine* engine)
{
	I_UEngine = engine;
}

void InstancesComponent::SetDatTime(class UDateTime* dateTime)
{
	I_UDateTime = dateTime;
}

void InstancesComponent::SetCanvas(class UCanvas* canvas)
{
	if (I_UCanvas != canvas)
	{
		I_UCanvas = canvas;
	}
}

void InstancesComponent::SetHUD(class AHUD* hud)
{
	if (I_AHUD != hud)
	{
		I_AHUD = hud;
	}
}

void InstancesComponent::SetGameViewportClient(class UGameViewportClient* viewportClient)
{
	if (I_UGameViewportClient != viewportClient)
	{
		I_UGameViewportClient = viewportClient;
	}
}

void InstancesComponent::SetPlayerController(class APlayerController* playerController)
{
	if (I_APlayerController != playerController)
	{
		I_APlayerController = playerController;
	}
}

void InstancesComponent::MapObjects()
{
	for (UObject* uObject : *UObject::GObjObjects())
	{
		if (uObject)
		{
			if (uObject->GetPackageName().ToString() != "Transient")
			{
				std::string objectFullName = uObject->GetFullName();

				if (objectFullName.find("Class ") == 0)
				{
					StaticClasses.emplace(objectFullName, reinterpret_cast<UClass*>(uObject));
				}
				else if (objectFullName.find("Function ") == 0)
				{
					StaticFunctions.emplace(objectFullName, reinterpret_cast<UFunction*>(uObject));
				}
			}
		}
	}
}


void InstancesComponent::Initialize()
{
	MapObjects();
	SetEngine(GetInstanceOf<UEngine>());
	SetDatTime(GetDefaultInstanceOf<UDateTime>());

	Console.Write(GetNameFormatted() + "Instances Initialized!");
}

class InstancesComponent Instances {};