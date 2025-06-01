package inventory.system.core.category;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import inventory.system.core.category.dto.CategoryDTO;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/categories")
@RequiredArgsConstructor
public class CategoryController {

    private final CategoryRepository categoryRepo;

    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    @PostMapping
    public ResponseEntity<?> create(@RequestBody CategoryDTO dto) {
        if (categoryRepo.existsByNameIgnoreCase(dto.getName())) {
            return ResponseEntity.badRequest().body("Category already exists.");
        }

        Category category = Category.builder()
                .name(dto.getName())
                .build();

        return ResponseEntity.ok(categoryRepo.save(category));
    }

    @GetMapping
    public Page<Category> list(
        @RequestParam(defaultValue = "") String search,
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "10") int size
    ) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return categoryRepo.findByNameContainingIgnoreCase(search, pageable);
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        return ResponseEntity.of(categoryRepo.findById(id));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Long id, @RequestBody CategoryDTO dto) {
        return categoryRepo.findById(id)
                .map(category -> {
                    category.setName(dto.getName());
                    return ResponseEntity.ok(categoryRepo.save(category));
                }).orElse(ResponseEntity.notFound().build());
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        if (!categoryRepo.existsById(id)) return ResponseEntity.notFound().build();
        categoryRepo.deleteById(id);
        return ResponseEntity.ok("Deleted");
    }
}