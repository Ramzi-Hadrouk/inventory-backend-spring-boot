package inventory.system.core.product;

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

import inventory.system.core.category.Category;
import inventory.system.core.category.CategoryRepository;
import inventory.system.core.product.dto.ProductDTO;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/v1/api/products")
@RequiredArgsConstructor
public class ProductController {

    private final ProductRepository productRepo;
    private final CategoryRepository categoryRepo;

    /*--------create product---- */
    @PreAuthorize("hasRole('ADMIN') or hasRole('MANAGER')")
    @PostMapping
    public ResponseEntity<?> create(@RequestBody ProductDTO dto) {
       
        Category category = categoryRepo.findById(dto.getCategoryId())
                .orElseThrow(() -> new RuntimeException("Category not found"));

        Product product = Product.builder()
                .name(dto.getName())
                .description(dto.getDescription())
                .price(dto.getPrice())
                .stock(dto.getStock())
                .category(category)
                .build();

        return ResponseEntity.ok(productRepo.save(product));
    }
    /*---------get products------- */
    @GetMapping
    public Page<Product> list(
        @RequestParam(defaultValue = "") String search,
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "10") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        return productRepo.findByNameContainingIgnoreCase(search, pageable);
    }

    /*------get one product by id------ */
    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        return ResponseEntity.of(productRepo.findById(id));
    }

    /*------update product by id------ */
    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable Long id, @RequestBody ProductDTO dto) {
        return productRepo.findById(id)
                .map(product -> {
                    product.setName(dto.getName());
                    product.setDescription(dto.getDescription());
                    product.setPrice(dto.getPrice());
                    product.setStock(dto.getStock());
                    product.setCategory(categoryRepo.findById(dto.getCategoryId())
                            .orElseThrow(() -> new RuntimeException("Category not found")));
                    return ResponseEntity.ok(productRepo.save(product));
                }).orElse(ResponseEntity.notFound().build());
    }

    /*--------delete product ------ */
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        if (!productRepo.existsById(id)) return ResponseEntity.notFound().build();
        productRepo.deleteById(id);
        return ResponseEntity.ok("Deleted");
    }
}
