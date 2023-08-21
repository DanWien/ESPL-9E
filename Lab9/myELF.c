#include <stdio.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>


struct fun_desc {
char *name;
void (*fun)();
};

int debug_mode = 0;
void *mapped = NULL;
int fd;             // File descriptor for the ELF file

struct ELF_file {
    int fd;
    struct stat fd_stat;
    void *mapped;
};

struct ELF_file elf_files[2];  // An array to hold the two ELF files
int current_file = 0;  // The index of the currently examined ELF file



void Toggle_Debug_Mode(){
    if(debug_mode == 1){
        debug_mode = 0;
        printf("Debug flag now off\n");
    }
    else{
        debug_mode = 1;
        printf("Debug flag now on\n");
    }
}

void examine_ELF_File() {
    char filename[100];
    Elf32_Ehdr *header;  // this will point to the header structure
    struct ELF_file *current;

    // If we have already examined two ELF files, print an error message and return
    if (current_file >= 2) {
        printf("Can't examine more than two ELF files!\n");
        return;
    }

    // Get a pointer to the current ELF_file structure
    current = &elf_files[current_file];

    // ask user for filename
    printf("Please enter the ELF file name: ");
    scanf("%s", filename);

    // Open file
    current->fd = open(filename, O_RDONLY);
    if (current->fd == -1) {
        perror("Error opening file for reading");
        exit(EXIT_FAILURE);
    }

    // Get the file size
    if (fstat(current->fd, &current->fd_stat) != 0) {
        perror("Stat failed");
        exit(EXIT_FAILURE);
    }

    // Memory map the file
    current->mapped = mmap(NULL, current->fd_stat.st_size, PROT_READ, MAP_PRIVATE, current->fd, 0);
    if (current->mapped == MAP_FAILED) {
        close(current->fd);
        perror("Error mmapping the file");
        exit(EXIT_FAILURE);
    }

    // The file is now available at the address pointed to by 'mapped'.
    header = (Elf32_Ehdr *)current->mapped;

    // Checking if the file is an ELF file
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3) {
        printf("This is not an ELF file!\n");
        munmap(current->mapped, current->fd_stat.st_size);
        close(current->fd);
        return;
    } 

    // Print out the information from the header
    printf("Magic Number bytes (in ASCII):\t%c%c%c\n",
        header->e_ident[EI_MAG1], header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);

    printf("Data encoding:\t\t\t");
    switch(header->e_ident[EI_DATA]){
        case ELFDATA2LSB: printf("2's complement, little endian\n"); break;
        case ELFDATA2MSB: printf("2's complement, big endian\n"); break;
        default: printf("Unknown data format\n");
    }

    printf("Entry point (in hexadecimal): \t0x%08x\n", header->e_entry);
    printf("Start of section headers: \t%d (bytes into file)\t\n", header->e_shoff);
    printf("Number of section headers: \t%d\t\n", header->e_shnum);
    printf("Size of each section header: \t%d\t\n", header->e_shentsize);
    printf("Start of program headers: \t%d (bytes into file)\t\n", header->e_phoff);
    printf("Number of program headers: \t%d\t\n", header->e_phnum);
    printf("Size of each program header: \t%d\t\n", header->e_phentsize);

    // Move to the next ELF file
    current_file++;
}


const char *find_sec_type(int sh_type) {
    switch(sh_type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_HASH: return "HASH";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_SHLIB: return "SHLIB";
        case SHT_DYNSYM: return "DYNSYM";
        default: return "UNKNOWN";
    }
}

void print_Sec_Names(){
    if (current_file == 0) {
        printf("No ELF file has been opened.\n");
        return;
    }

    for (int i = 0; i < current_file; i++) {
        printf("File %d\n", i);
        if(debug_mode)
            printf("[Num] Name\t\tAddr\tOff\tSize\tType\tOffset(bytes)\n");
        else
            printf("[Num] Name\t\tAddr\tOff\tSize\tType\n");

        struct ELF_file *current = &elf_files[i];
        Elf32_Ehdr *header = (Elf32_Ehdr *)current->mapped;
        Elf32_Shdr *sections = (Elf32_Shdr *)((char *)header + header->e_shoff);
        char *strtab = (char *)header + sections[header->e_shstrndx].sh_offset;

        for (int j = 0; j < header->e_shnum; j++) {
            if (debug_mode == 1) {
                printf("[%d] %-18s %08x %06x %06x %s\t%d\n",
                       j,
                       &strtab[sections[j].sh_name],
                       sections[j].sh_addr,
                       sections[j].sh_offset,
                       sections[j].sh_size,
                       find_sec_type(sections[j].sh_type),
                       header->e_shoff + j * header->e_shentsize);
            } else {
                printf("[%d] %-18s %08x %06x %06x %s\n",
                       j,
                       &strtab[sections[j].sh_name],
                       sections[j].sh_addr,
                       sections[j].sh_offset,
                       sections[j].sh_size,
                       find_sec_type(sections[j].sh_type));
            }
        }
    }
}

void print_Symbols(){
    if (current_file == 0) {
        printf("No ELF file has been opened.\n");
        return;
    }

    for (int i = 0; i < current_file; i++) {
        printf("File %d\n", i);

        if (debug_mode == 1) {
            printf("[Num]\tValue\t\tsection_index\tsection_name\t\tsymbol_name\tsize\n");
        } else {
            printf("[Num]\tValue\t\tsection_index\tsection_name\t\tsymbol_name\n");
        }

        struct ELF_file *current = &elf_files[i];
        Elf32_Ehdr *header = (Elf32_Ehdr *)current->mapped;
        Elf32_Shdr *sections = (Elf32_Shdr *)((char *)header + header->e_shoff);

        int symtab_index = -1;
        for (int j = 0; j < header->e_shnum; j++) {
            if (sections[j].sh_type == SHT_SYMTAB) {
                symtab_index = j;
                break;
            }
        }

        if (symtab_index == -1) {
            printf("No symbol table found in the ELF file.\n");
            return;
        }

        Elf32_Sym *symbols = (Elf32_Sym *)((char *)header + sections[symtab_index].sh_offset);
        int symbol_count = sections[symtab_index].sh_size / sizeof(Elf32_Sym);
        char *strtab = (char *)header + sections[sections[symtab_index].sh_link].sh_offset;

        for (int j = 0; j < symbol_count; j++) {
            printf("[%d]\t%08x\t%d\t\t%-18s\t%s\n",
                   j,
                   symbols[j].st_value,
                   symbols[j].st_shndx,
                   (symbols[j].st_shndx >= SHN_LORESERVE) ? "ABS" : &strtab[sections[symbols[j].st_shndx].sh_name],
                   &strtab[symbols[j].st_name]);
        }
    }
}

Elf32_Sym *find_symbol(Elf32_Sym *symtab, int symtab_size, char *strtab, char *symbol_name) {
    for (int i = 1; i < symtab_size; i++) {
        if (strcmp(&strtab[symtab[i].st_name], symbol_name) == 0) {
            return &symtab[i];
        }
    }
    return NULL;
}

int symbol_defined(Elf32_Sym *symbol) {
    return symbol->st_shndx != SHN_UNDEF;
}

void check_For_Merge() {
    if (current_file != 2) {
        printf("Must have exactly two ELF files opened!\n");
        return;
    }

    struct ELF_file *file1 = &elf_files[0];
    struct ELF_file *file2 = &elf_files[1];
    

    Elf32_Shdr *sections1 = (Elf32_Shdr *)((char *)file1->mapped + ((Elf32_Ehdr *)file1->mapped)->e_shoff);
    Elf32_Shdr *sections2 = (Elf32_Shdr *)((char *)file2->mapped + ((Elf32_Ehdr *)file2->mapped)->e_shoff);

    int symtab_index1 = -1, symtab_index2 = -1;
    for (int i = 0; i < ((Elf32_Ehdr *)file1->mapped)->e_shnum; i++) {
        if (sections1[i].sh_type == SHT_SYMTAB) {
            symtab_index1 = i;
            break;
        }
    }
    for (int i = 0; i < ((Elf32_Ehdr *)file2->mapped)->e_shnum; i++) {
        if (sections2[i].sh_type == SHT_SYMTAB) {
            symtab_index2 = i;
            break;
        }
    }

    if (symtab_index1 == -1 || symtab_index2 == -1) {
        printf("Both files must have a symbol table!\n");
        return;
    }

    Elf32_Sym *symtab1 = (Elf32_Sym *)((char *)file1->mapped + sections1[symtab_index1].sh_offset);
    Elf32_Sym *symtab2 = (Elf32_Sym *)((char *)file2->mapped + sections2[symtab_index2].sh_offset);
    int symtab_size1 = sections1[symtab_index1].sh_size / sizeof(Elf32_Sym);
    int symtab_size2 = sections2[symtab_index2].sh_size / sizeof(Elf32_Sym);

    char *strtab1 = (char *)file1->mapped + sections1[sections1[symtab_index1].sh_link].sh_offset;
    char *strtab2 = (char *)file2->mapped + sections2[sections2[symtab_index2].sh_link].sh_offset;

    int mergeFlag = 1;
    for (int i = 2; i < symtab_size1; i++) {
        Elf32_Sym *sym = &symtab1[i];
        char *symbol_name = &strtab1[sym->st_name];
    
        // printf("Current symbol : %s , current index : %d\n" , symbol_name , i);
        Elf32_Sym *sym2 = find_symbol(symtab2, symtab_size2, strtab2, symbol_name);

        if(strcmp(symbol_name, "") != 0) {
            if (!symbol_defined(sym)) {
                if (sym2 == NULL || !symbol_defined(sym2)) {
                    printf("Symbol %s undefined!\n", symbol_name);
                    mergeFlag = 0;
                }
            } else {
                if (sym2!=NULL && symbol_defined(sym2)) {
                    printf("Symbol %s multiply defined!\n", symbol_name);
                    mergeFlag = 0;
                }
            }
        }
    }
    if(mergeFlag)
        printf("Files can be merged!\n");
    else
        printf("Files can not be merged!\n");
}

Elf32_Shdr* find_sec(Elf32_Shdr* sections, int size, char* shstrtab, char* name){
    for(int i = 0; i < size; i++){
        if(strcmp(name, &shstrtab[sections[i].sh_name]) == 0){
            return &sections[i];
        }
    }
    return NULL;
}


void merge_ELF_Files(){
    if(current_file != 2){
        printf("Must have exactly two ELF files opened!\n");
        return;
    }
    struct ELF_file *file1 = &elf_files[0];
    struct ELF_file *file2 = &elf_files[1];

    Elf32_Ehdr* new_header = (Elf32_Ehdr *)file1->mapped;
    Elf32_Shdr* Shdr1 = (Elf32_Shdr*) (file1->mapped + new_header->e_shoff);
    Elf32_Shdr* sec1_names = &Shdr1[new_header->e_shstrndx];
    Elf32_Ehdr* header2 = (Elf32_Ehdr*) file2->mapped;
    Elf32_Shdr* Shdr2 = (Elf32_Shdr*) (file2->mapped + header2->e_shoff);
    Elf32_Shdr* sec2_names = &Shdr2[header2->e_shstrndx];
    char* shstrtab1 = (char*)(file1->mapped + sec1_names->sh_offset);
    char* shstrtab2 = (char*)(file2->mapped + sec2_names->sh_offset);

    FILE* file;
    if((file = fopen("out.ro", "wb")) == NULL);{
        printf("Failed to create out.ro");
        return;
    }
    fwrite((char*)new_header, 1, new_header->e_ehsize, file); 
    Elf32_Shdr shdr[new_header->e_shnum];
    memcpy(shdr, Shdr1, new_header->e_shnum * new_header->e_shentsize); 
    Elf32_Sym* symbols1 = NULL;
    int sym1_size;
    char* strtab1;
    for(int i = 0; i < new_header->e_shnum; i++){
        if(Shdr1[i].sh_type == SHT_SYMTAB || Shdr1[i].sh_type == SHT_DYNSYM){
            symbols1 = (Elf32_Sym*)(file1->mapped + Shdr1[i].sh_offset);
            sym1_size = Shdr1[i].sh_size / Shdr1[i].sh_entsize;
            strtab1 = (char*)(file1->mapped + Shdr1[Shdr1[i].sh_link].sh_offset);
        }
    }

    Elf32_Sym* symbols2 = NULL;
    int sym2_size;
    char* strtab2;
    for(int i = 0; i < header2->e_shnum; i++){
        if(Shdr2[i].sh_type == SHT_SYMTAB || Shdr2[i].sh_type == SHT_DYNSYM){
            symbols2 = (Elf32_Sym*)(file2->mapped + Shdr2[i].sh_offset);
            sym2_size = Shdr2[i].sh_size / Shdr2[i].sh_entsize;
            strtab2 = (char*)(file2->mapped + Shdr2[Shdr2[i].sh_link].sh_offset);
        }
    }

    for(int i = 1; i < new_header->e_shnum; i++){
        shdr[i].sh_offset = ftell(file);
        char* section_name = &shstrtab1[Shdr1[i].sh_name];
        if(strcmp(section_name, ".text") == 0 || strcmp(section_name, ".data") == 0 || strcmp(section_name, ".rodata") == 0){
            fwrite((char*)(file1->mapped + Shdr1[i].sh_offset), 1, Shdr1[i].sh_size, file);
            Elf32_Shdr* section = find_sec(Shdr2, header2->e_shnum, shstrtab2, section_name);
            if(section != NULL){
                fwrite((char*)(file2->mapped + section->sh_offset), 1, section->sh_size, file);
                shdr[i].sh_size = Shdr1[i].sh_size + section->sh_size;
            }
        } else if(strcmp(section_name, ".symtab") == 0){
            Elf32_Sym symbols[sym1_size];
            memcpy((char*)symbols, (char*)symbols1, Shdr1[i].sh_size);
            for(int j = 1; j < sym1_size; j++){
                if(symbols1[j].st_shndx == SHN_UNDEF){
                    Elf32_Sym* symbol = find_symbol(symbols2, sym2_size, strtab2, &strtab1[symbols1[j].st_name]);
                    symbols[j].st_value = symbol->st_value;
                    char* section_name2 = &shstrtab2[Shdr2[symbol->st_shndx].sh_name];
                    Elf32_Shdr* section = find_sec(Shdr1, new_header->e_shnum, shstrtab1, section_name2);
                    symbols[j].st_shndx = section - Shdr1;
                    
                }
            }
            fwrite((char*)symbols, 1, Shdr1[i].sh_size, file);
        } else {
            fwrite((char*)(file1->mapped + Shdr1[i].sh_offset), 1, Shdr1[i].sh_size, file);
        }
    }


    int offset = ftell(file);
    fwrite((char*)shdr, 1, new_header->e_shnum * new_header->e_shentsize, file);
    fseek(file, 32, SEEK_SET); 
    fwrite((char*)(&offset), 1, sizeof(int), file);
    fclose(file);
}


void refresh_Files() {
    for (int i = 0; i < 2; i++) {
        if (elf_files[i].fd != -1) {
            close(elf_files[i].fd);
            elf_files[i].fd = -1;
        }

        // Clear the 'fd_stat' struct
        memset(&(elf_files[i].fd_stat), 0, sizeof(struct stat));

        // Free the 'mapped' memory if not NULL
        if (elf_files[i].mapped != NULL) {
            munmap(elf_files[i].mapped, elf_files[i].fd_stat.st_size);
            elf_files[i].mapped = NULL;
        }
    }
    current_file = 0;
}

 
void quit() {
    for (int i = 0; i < current_file; i++) {
        if (elf_files[i].mapped != NULL) {
            munmap(elf_files[i].mapped, elf_files[i].fd_stat.st_size);
        }
        if (elf_files[i].fd != -1) {
            close(elf_files[i].fd);
        }
    }
    if(debug_mode==1)
        printf("quitting\n");
    exit(0);
}



struct fun_desc menu[] ={
    {"Toggle Debug Mode", Toggle_Debug_Mode},
    {"Examine ELF File", examine_ELF_File},
    {"Print Section Names", print_Sec_Names},
    {"Print Symbols", print_Symbols},
    {"Check Files for Merge", check_For_Merge},
    {"Merge ELF Files", merge_ELF_Files},
    {"Refresh Files", refresh_Files},
    {"Quit", quit},
    {NULL, NULL}
};


int main(int argc, char **argv){
    int menu_len=8;
    int num;
    while(1){
        printf("Select operation from the following menu:\n");
        for(int i=0; i<menu_len; i++){
            printf("%d-%s\n",i,menu[i].name);
        }
        printf("Option: ");
        scanf("%d" , &num);
        int c;
        while ((c = getchar()) != '\n' && c != EOF) { }
        if((num>=0) & (num<=menu_len)){
            printf("Within bounds\n");
            menu[num].fun();
        }
        else{
            printf("Not within bounds\n");
            exit(1);
        }

    }
    return 0;
}