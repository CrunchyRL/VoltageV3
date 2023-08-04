//#include "MemoryAllocator.hpp"
//
//MemoryAllocator::MemoryAllocator(size_t PoolSize) {
//	MemoryPool = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE,((1024*1024)*PoolSize), 1);
//	HeapLock(MemoryPool);
//}
//
//MemoryAllocator::~MemoryAllocator() {
//	HeapDestroy(MemoryPool);
//}
//
//void MemoryAllocator::RegisterObject(UObject* Object, std::string ObjectName) {
//	FNameEntry* ObjectNameEntry = reinterpret_cast<FNameEntry*>(HeapAlloc(MemoryPool, HEAP_ZERO_MEMORY, sizeof(FName)));
//	ObjectName = ObjectName + ".VoltageObject";
//	strcpy((char*)ObjectNameEntry->Name, ObjectName.c_str());
//	GNames->Add(ObjectNameEntry);
//	reinterpret_cast<UObject*>(Object)->Name = FName(ObjectNameEntry->Index);
//}
//
